#!/usr/bin/env python3
"""
One-off: fix the 44 duplicate-object pairs created by get_or_create_network()
(common/net_helpers.py) generating its own NET_<value>/HOST_<value> name
instead of reusing the pre-existing, correctly ASA-named object for the same
value. Both objects exist live on the FTD; whichever migrate_*.py script ran
(migrate_s2s_vpn.py, migrate_routes.py, migrate_access_control.py,
migrate_http_access.py, migrate_icmp.py, migrate_nat.py, migrate_snmp.py --
all share get_or_create_network) referenced the ugly-named duplicate's id.

For each pair:
  1. Scan every collection any of those scripts could have written a network
     reference into (network groups, access rules, manual/auto NAT rules,
     static routes, S2S VPN profiles, HTTPS mgmt access, ICMP rules, SNMP
     hosts) for a {"id": <duplicate-id>, ...} reference, found generically by
     walking each item's JSON body (no dependency on exact field names).
  2. If found, PUT the item back with that reference's id/name swapped to
     the canonical (real ASA name) object.
  3. Once nothing references the duplicate, DELETE it.

Without --apply, only reports what it would touch (all GETs, no writes).

Usage:
    python dedupe_network_objects.py --config config.yaml            # preview
    python dedupe_network_objects.py --config config.yaml --apply    # do it
"""
import argparse
import json
import re
from collections import defaultdict

from common.fdm_client import load_config, build_client, FdmApiError

NETWORKS_PATH = "object/networks"
GROUPS_PATH = "object/networkgroups"
MANUAL_NAT_POLICIES_PATH = "policy/manualnatpolicies"
AUTO_NAT_PATH = "devices/default/objectnats"
ACCESS_POLICIES_PATH = "policy/accesspolicies"
VIRTUAL_ROUTERS_PATH = "devices/default/routing/virtualrouters"
S2SVPN_PATH = "devices/default/s2sconnectionprofiles"
HTTP_ACCESS_PATH = "devicesettings/default/managementaccess"
ICMP_PATH = "devicesettings/default/icmp"
SNMP_HOSTS_PATH = "object/snmphosts"

# This toolkit's get_or_create_network() (common/net_helpers.py) names an
# auto-created object "NET_<ip>-<...>-<prefix>" / "HOST_<ip>-<...>" -- dashes
# only, no dots -- distinct from FDM's own dot-preserving auto-names (e.g.
# "NET_192.168.0.0_16") and from real ASA object names.
TOOLKIT_GENERATED_RE = re.compile(r"^(NET|HOST)_[0-9]+(-[0-9]+)*$")

# For a value with more than one non-toolkit-generated name already on the
# device (a pre-existing ASA-side naming duplicate, unrelated to this
# toolkit), the choice of which one survives isn't automatic -- confirmed
# with a human for each case as they turned up:
CANONICAL_OVERRIDES = {
    ("NETWORK", "10.100.8.0/21"): "BastionAzure",
    ("NETWORK", "10.100.107.0/24"): "IDBC_A2Com",
    ("HOST", "212.51.187.89"): "Peer_Pulsy_eMage",
    ("NETWORK", "10.0.0.0/8"): "IPv4-Private-10.0.0.0-8",
    ("NETWORK", "192.168.0.0/16"): "IPv4-Private-192.168.0.0-16",
}


def discover_duplicates(client, net_path):
    """Group live network objects by (subType, value); for each group with a
    toolkit-generated duplicate, pick a canonical survivor and return
    {dup_id: (canonical_id, canonical_name)} plus {dup_id: (dup_name, canonical_name)}
    for reporting. Groups needing a human call that CANONICAL_OVERRIDES
    doesn't cover are reported separately and skipped."""
    by_value = defaultdict(list)
    for obj in client.get_all_pages(net_path):
        by_value[(obj.get("subType"), obj.get("value"))].append(obj)

    id_map, dup_id_to_names, unresolved = {}, {}, []
    for key, objs in by_value.items():
        toolkit_objs = [o for o in objs if TOOLKIT_GENERATED_RE.match(o["name"])]
        other_objs = [o for o in objs if not TOOLKIT_GENERATED_RE.match(o["name"])]
        if not toolkit_objs or not other_objs:
            continue  # no toolkit dup here, or nothing else to merge it into

        if len(other_objs) == 1:
            canonical = other_objs[0]
        else:
            override_name = CANONICAL_OVERRIDES.get(key)
            canonical = next((o for o in other_objs if o["name"] == override_name), None)
            if canonical is None:
                unresolved.append((key, [o["name"] for o in objs]))
                continue

        for o in objs:
            if o["id"] == canonical["id"]:
                continue
            id_map[o["id"]] = (canonical["id"], canonical["name"])
            dup_id_to_names[o["id"]] = (o["name"], canonical["name"])

    return id_map, dup_id_to_names, unresolved


def replace_refs(obj, id_map, path=()):
    """Recursively walk obj, replacing any {"id": <dup-id>, ...} dict's id
    (and name, if present) with the canonical id/name. Returns list of
    (path, old_id, new_id) for every replacement made, mutating obj in place."""
    hits = []
    if isinstance(obj, dict):
        oid = obj.get("id")
        if oid in id_map:
            new_id, new_name = id_map[oid]
            obj["id"] = new_id
            if "name" in obj and obj["name"] is not None:
                obj["name"] = new_name
            hits.append((path, oid, new_id))
        for k, v in obj.items():
            hits.extend(replace_refs(v, id_map, path + (k,)))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            hits.extend(replace_refs(v, id_map, path + (i,)))
    return hits


def scan_and_fix_collection(client, path, id_map, apply, label, touched):
    try:
        items = client.get_all_pages(path)
    except FdmApiError as e:
        print(f"  ! could not read {label} ({path}): {e} -- skipping this collection")
        return
    for item in items:
        raw = json.dumps(item)
        if not any(dup_id in raw for dup_id in id_map):
            continue
        body = dict(item)
        body.pop("links", None)
        hits = replace_refs(body, id_map)
        if not hits:
            continue
        for _, old_id, new_id in hits:
            touched.setdefault(old_id, []).append(
                f"{label}: '{item.get('name', item.get('id'))}' (id={item.get('id')})")
        if apply:
            try:
                client.put(f"{path}/{item['id']}", body)
                print(f"  + updated {label} '{item.get('name', item.get('id'))}' "
                      f"(id={item.get('id')}) -- {len(hits)} reference(s) repointed")
            except FdmApiError as e:
                print(f"  ! failed to update {label} '{item.get('name', item.get('id'))}' "
                      f"(id={item.get('id')}): {e}")
        else:
            print(f"  would update {label} '{item.get('name', item.get('id'))}' "
                  f"(id={item.get('id')}) -- {len(hits)} reference(s) to repoint")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--apply", action="store_true",
                     help="Actually repoint references and delete duplicates. "
                          "Without this flag, only scans and reports.")
    args = ap.parse_args()

    cfg = load_config(args.config)
    client = build_client(cfg)

    net_path = client.resolve_endpoint(NETWORKS_PATH, ["network"])

    id_map, dup_id_to_names, unresolved = discover_duplicates(client, net_path)

    if unresolved:
        print(f"{len(unresolved)} value(s) have a toolkit duplicate plus more than one "
              f"other existing name, with no CANONICAL_OVERRIDES entry to pick a survivor "
              f"-- skipped, resolve by hand or add an override:")
        for (sub_type, value), names in unresolved:
            print(f"  {sub_type} {value}: {names}")
        print()

    print(f"Resolved {len(id_map)} duplicate(s) to fix.\n")

    touched = {}

    groups_path = client.resolve_endpoint(GROUPS_PATH, ["network", "group"])
    scan_and_fix_collection(client, groups_path, id_map, args.apply, "network group", touched)

    s2s_path = client.resolve_endpoint(S2SVPN_PATH, ["s2s", "connection"])
    scan_and_fix_collection(client, s2s_path, id_map, args.apply, "S2S VPN profile", touched)

    http_path = client.resolve_endpoint(HTTP_ACCESS_PATH, ["management", "access"])
    scan_and_fix_collection(client, http_path, id_map, args.apply, "HTTPS mgmt access entry", touched)

    icmp_path = client.resolve_endpoint(ICMP_PATH, ["icmp"])
    scan_and_fix_collection(client, icmp_path, id_map, args.apply, "ICMP rule", touched)

    snmp_path = client.resolve_endpoint(SNMP_HOSTS_PATH, ["snmp", "host"])
    scan_and_fix_collection(client, snmp_path, id_map, args.apply, "SNMP host", touched)

    auto_nat_path = client.resolve_endpoint(AUTO_NAT_PATH, ["object", "nat"])
    scan_and_fix_collection(client, auto_nat_path, id_map, args.apply, "auto NAT rule", touched)

    manual_nat_policies_path = client.resolve_endpoint(MANUAL_NAT_POLICIES_PATH, ["manual", "nat", "polic"])
    try:
        nat_policies = client.get_all_pages(manual_nat_policies_path)
    except FdmApiError as e:
        print(f"  ! could not list manual NAT policies: {e}")
        nat_policies = []
    for pol in nat_policies:
        rules_path = f"{manual_nat_policies_path}/{pol['id']}/manualnatrules"
        scan_and_fix_collection(client, rules_path, id_map, args.apply,
                                 f"manual NAT rule ({pol.get('name')})", touched)

    access_policies_path = client.resolve_endpoint(ACCESS_POLICIES_PATH, ["access", "polic"])
    try:
        acps = client.get_all_pages(access_policies_path)
    except FdmApiError as e:
        print(f"  ! could not list access policies: {e}")
        acps = []
    for pol in acps:
        rules_path = f"{access_policies_path}/{pol['id']}/accessrules"
        scan_and_fix_collection(client, rules_path, id_map, args.apply,
                                 f"access rule ({pol.get('name')})", touched)

    vr_path = client.resolve_endpoint(VIRTUAL_ROUTERS_PATH, ["virtualrouter"])
    try:
        vrs = client.get_all_pages(vr_path)
    except FdmApiError as e:
        print(f"  ! could not list virtual routers: {e}")
        vrs = []
    for vr in vrs:
        routes_path = f"{vr_path}/{vr['id']}/staticrouteentries"
        scan_and_fix_collection(client, routes_path, id_map, args.apply,
                                 f"static route ({vr.get('name')})", touched)

    print(f"\n{'Repointed' if args.apply else 'Would repoint'} references for "
          f"{len(touched)} of {len(id_map)} duplicate object(s).")
    for dup_id, (old_name, new_name) in dup_id_to_names.items():
        refs = touched.get(dup_id, [])
        print(f"\n{old_name} -> {new_name} (id={dup_id}):")
        if not refs:
            print("  no references found -- safe to delete with no repointing needed")
        else:
            for r in refs:
                print(f"  {r}")

    if not args.apply:
        print("\nPreview only -- no changes sent. Re-run with --apply to repoint and delete.")
        return

    print("\nDeleting now-unreferenced duplicate objects...")
    deleted, delete_errors = 0, []
    for dup_id, (old_name, new_name) in dup_id_to_names.items():
        try:
            client.delete(f"{net_path}/{dup_id}")
            print(f"  - deleted '{old_name}' (id={dup_id})")
            deleted += 1
        except FdmApiError as e:
            print(f"  ! failed to delete '{old_name}' (id={dup_id}): {e}")
            delete_errors.append((old_name, str(e)))

    print(f"\nDeleted {deleted}/{len(dup_id_to_names)}.")
    if delete_errors:
        print("Still referenced somewhere not scanned by this script -- resolve by hand in FDM:")
        for name, err in delete_errors:
            print(f"  {name}: {err}")

    print("\nAll changes are staged as pending in FDM -- not deployed. Review and "
          "deploy by hand, or via migrate_network_objects.py's deploy prompt.")


if __name__ == "__main__":
    main()
