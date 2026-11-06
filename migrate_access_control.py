#!/usr/bin/env python3
"""
Create Access Control Policy rules on FTD permitting site-to-site VPN
traffic (parsed by parse_asa_config.py), matching each tunnel's local and
remote networks. This is required because, unlike ASA's default `sysopt
connection permit-vpn` (which bypasses the interface ACL for decrypted VPN
traffic), FTD's Access Control Policy does NOT exempt decrypted VPN traffic
by default -- a tunnel can be fully up (Phase 1/2 established) while zero
traffic actually passes, because nothing permits it through the ACP.

Usage:
    python migrate_access_control.py --config config.yaml --in-dir parsed/

Endpoint (policy/accesspolicies/{id}/accessrules), the accessrule type, and
the ruleAction/sourceZones/destinationZones/sourceNetworks/destinationNetworks
field names below were confirmed against a live FTD 7.6.x AccessRule (note
it's `ruleAction`, not `action`). Two rules are created per tunnel -- one per
direction (VPN_<peer>_OUT: internal zone/local networks -> outside
zone/remote networks, and VPN_<peer>_IN: the reverse) -- matching the
confirmed real rule's own single-zone-each-side, single-direction shape
rather than combining both directions into one rule; FTD's ACP is stateful,
so each rule's return traffic is already covered, but either side of a
site-to-site tunnel can initiate a new connection, hence two rules.

Still open, deliberately not attempted here because guessing them wrong
would be worse than not touching them:
  - Rule ORDER. This script doesn't try to position new rules ahead of an
    existing broad/deny-all rule (FDM's ordering mechanism for creating
    accessrules isn't confirmed), so they may get appended at the end where
    a catch-all deny would shadow them. ALWAYS check rule order in FDM
    before deploying -- the script prints what the current last rule in the
    policy is before creating anything, so you can judge that up front.
  - Protocol/port granularity. If your ASA's crypto-map ACL restricted
    specific protocols/ports (rather than a blanket `permit ip`), that's not
    carried over -- every rule here permits all traffic between the local
    and remote networks. (The parser doesn't extract per-protocol ACL
    entries today.)
  - Rarer AccessRule fields seen on a live rule but not set here
    (intrusionPolicy, filePolicy, timeRangeObjects, identitySources, etc.)
    are left at their server-side defaults.
"""
import argparse
import json
import os

from common.fdm_client import load_config, build_client, FdmApiError
from common.net_helpers import get_or_create_network, classify_cidr_or_range, NETWORKS_PATH

ACCESS_POLICIES_PATH = "policy/accesspolicies"      # confirmed against a live device
SECURITY_ZONES_PATH = "object/securityzones"        # best guess -- the "securityzone" ref
                                                     # type is confirmed (seen embedded in a
                                                     # real accessrule), but this listing
                                                     # endpoint itself hasn't been checked
INTERFACES_PATH = "devices/default/interfaces"


def find_interface(client, iface_path, logical_name):
    interfaces = client.get_all_pages(iface_path)
    for iface in interfaces:
        if iface.get("name") == logical_name or iface.get("hardwareName") == logical_name:
            return iface
    return None


def find_zone_for_interface(client, zone_path, iface_id):
    zones = client.get_all_pages(zone_path)
    for z in zones:
        if any(i["id"] == iface_id for i in z.get("interfaces", [])):
            return {"id": z["id"], "type": z.get("type", "securityzone")}
    return None


def resolve_zone(client, iface_path, zone_path, ftd_iface_name):
    if not ftd_iface_name:
        return None
    if client.dry_run:
        return {"id": f"dryrun-zone-{ftd_iface_name}", "type": "securityzone"}
    iface = find_interface(client, iface_path, ftd_iface_name)
    if not iface:
        print(f"  ! FTD interface '{ftd_iface_name}' not found, can't resolve its zone")
        return None
    zone = find_zone_for_interface(client, zone_path, iface["id"])
    if not zone:
        print(f"  ! interface '{ftd_iface_name}' isn't assigned to a security zone")
    return zone


def networks_to_refs(client, net_path, cidrs, skip_existing):
    refs = []
    for cidr in cidrs:
        if cidr.startswith("UNRESOLVED") or cidr.startswith("OBJECT:"):
            print(f"    ! skipping unresolved network reference '{cidr}' in ACP rule -- "
                  f"add it manually in FDM")
            continue
        sub_type, value = classify_cidr_or_range(cidr)
        refs.append(get_or_create_network(client, net_path, value, sub_type, skip_existing))
    return refs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--in-dir", default="parsed")
    args = ap.parse_args()

    cfg = load_config(args.config)
    skip_existing = cfg.get("options", {}).get("skip_existing", True)
    iface_map = cfg.get("interface_map", {})
    client = build_client(cfg)

    with open(os.path.join(args.in_dir, "vpn.json")) as f:
        vpn_data = json.load(f)

    net_path = client.resolve_endpoint(NETWORKS_PATH, ["network"])
    iface_path = client.resolve_endpoint(INTERFACES_PATH, ["interfaces"])
    zone_path = client.resolve_endpoint(SECURITY_ZONES_PATH, ["security", "zone"])
    policies_path = client.resolve_endpoint(ACCESS_POLICIES_PATH, ["access", "polic"])

    if client.dry_run:
        rules_path = f"{policies_path}/dryrun-policy/accessrules"
    else:
        policies = client.get_all_pages(policies_path)
        if not policies:
            print("! no access control policy found on this device -- cannot create rules. "
                  f"Endpoint used: {policies_path} -- if this 404s, the path is wrong, see "
                  f"the docstring's request for real API Explorer data.")
            return
        policy_id = policies[0]["id"]
        rules_path = f"{policies_path}/{policy_id}/accessrules"
        existing_rules = client.get_all_pages(rules_path)
        if existing_rules:
            last = existing_rules[-1]
            print(f"  ! this policy already has {len(existing_rules)} rule(s); the last one "
                  f"is '{last.get('name')}' (ruleAction={last.get('ruleAction')}) -- new rules from "
                  f"this script may be appended AFTER it. If that's a broad/deny-all rule, "
                  f"the VPN rule(s) below will be shadowed. Verify and reorder in FDM before "
                  f"deploying.")

    schema = client.get_schema_properties(rules_path)
    print(f"Access rule endpoint resolved to: {rules_path}")
    print(f"Expected top-level fields per live schema: "
          f"{sorted(schema) if schema else '(could not read schema -- endpoint/model unverified, see docstring)'}")

    created = 0
    for tunnel in vpn_data["tunnels"]:
        peer = tunnel.get("peer")
        if not peer or not tunnel.get("local_networks") or not tunnel.get("remote_networks"):
            continue
        outside_asa_iface = tunnel["interface"]
        outside_ftd_name = iface_map.get(outside_asa_iface)
        if not outside_ftd_name:
            print(f"  ! no interface_map entry for '{outside_asa_iface}', skipping ACP rule "
                  f"for tunnel to {peer}")
            continue
        internal_ftd_name = iface_map.get(tunnel.get("nat_exempt_interface") or "")

        try:
            outside_zone_ref = resolve_zone(client, iface_path, zone_path, outside_ftd_name)
            internal_zone_ref = (resolve_zone(client, iface_path, zone_path, internal_ftd_name)
                                  if internal_ftd_name else None)
        except FdmApiError as e:
            print(f"  ! could not look up security zones for tunnel to {peer} ({e}) -- "
                  f"creating rule(s) without zone restriction; verify SECURITY_ZONES_PATH "
                  f"in migrate_access_control.py against your device")
            outside_zone_ref = None
            internal_zone_ref = None
        if not internal_zone_ref:
            print(f"  ! could not determine the internal-side zone for tunnel to {peer} "
                  f"(check nat_exempt_interface in vpn.json / interface_map) -- creating "
                  f"rule(s) without a source/destination zone restriction on that side")

        print(f"Building ACP rule(s) for tunnel to {peer}...")
        try:
            local_refs = networks_to_refs(client, net_path, tunnel["local_networks"], skip_existing)
            remote_refs = networks_to_refs(client, net_path, tunnel["remote_networks"], skip_existing)
        except FdmApiError as e:
            print(f"  ! failed to resolve networks for ACP rule(s) on tunnel to {peer}: {e}")
            continue

        # Two unidirectional rules, matching FTD's own convention (confirmed
        # against a live rule): one per initiation direction. FTD's ACP is
        # stateful, so either rule alone would cover that direction's return
        # traffic too, but either side of a site-to-site tunnel can initiate.
        directions = [
            ("OUT", local_refs, remote_refs, internal_zone_ref, outside_zone_ref),
            ("IN", remote_refs, local_refs, outside_zone_ref, internal_zone_ref),
        ]
        for suffix, src_nets, dst_nets, src_zone, dst_zone in directions:
            body = {
                "name": f"VPN_{peer.replace('.', '-')}_{suffix}",
                "type": "accessrule",
                "ruleAction": "PERMIT",
                "eventLogAction": "LOG_NONE",
                "sourceNetworks": src_nets,
                "destinationNetworks": dst_nets,
            }
            if src_zone:
                body["sourceZones"] = [src_zone]
            if dst_zone:
                body["destinationZones"] = [dst_zone]
            try:
                client.create_or_reuse(rules_path, body, skip_existing)
                created += 1
            except FdmApiError as e:
                print(f"  ! failed to create ACP rule '{body['name']}': {e}\n"
                      f"    Compare the request above against "
                      f"https://{client.host}/#/api-explorer and fix the body fields in "
                      f"migrate_access_control.py, then re-run (rules already created are "
                      f"reused by name via skip_existing, not duplicated).")

    print(f"Processed {len(vpn_data['tunnels'])} tunnel(s), created/reused {created} "
          f"access control rule(s).")
    print("IMPORTANT: verify rule order in FDM before deploying -- a rule appended after an "
          "existing broad/deny-all rule will never be evaluated.")

    if not client.dry_run:
        deploy = input("Deploy these changes to the device now? [y/N] ").strip().lower()
        if deploy == "y":
            client.deploy()
        else:
            print("Skipped deploy -- ACP rules are staged as pending changes in FDM.")


if __name__ == "__main__":
    main()
