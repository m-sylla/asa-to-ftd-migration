#!/usr/bin/env python3
"""
One-off: find network object-groups that exist on the live FTD but aren't
referenced anywhere on the device -- not as a member of another group, and
not by an S2S VPN profile, access rule, manual/auto NAT rule, static route,
SNMP host, or any of the HTTPS/SSH/data-interface management access lists.

Live-device counterpart to find_unused_objects.py's `unused_groups` (which
analyzes the ASA config text only) -- same rationale as
find_unused_network_objects_live.py for network objects. Reports only --
does not delete anything.

Usage:
    python find_unused_network_groups_live.py --config config.yaml
"""
import argparse
import json

from common.fdm_client import load_config, build_client, FdmApiError

GROUPS_PATH = "object/networkgroups"
MANUAL_NAT_POLICIES_PATH = "policy/manualnatpolicies"
AUTO_NAT_POLICIES_PATH = "policy/objectnatpolicies"
ACCESS_POLICIES_PATH = "policy/accesspolicies"
VIRTUAL_ROUTERS_PATH = "devices/default/routing/virtualrouters"
S2SVPN_PATH = "devices/default/s2sconnectionprofiles"
HTTP_ACCESS_LISTS_PATH = "devicesettings/default/httpaccesslists"
SSH_ACCESS_LISTS_PATH = "devicesettings/default/sshaccesslists"
MANAGEMENT_ACCESS_PATH = "devicesettings/default/managementaccess"
ICMP_PATH = "devicesettings/default/icmp"
SNMP_HOSTS_PATH = "object/snmphosts"


def collect_referenced_ids(client, path, label, referenced):
    try:
        items = client.get_all_pages(path)
    except FdmApiError as e:
        print(f"  ! could not read {label} ({path}): {e} -- skipping")
        return
    for item in items:
        raw = json.dumps(item)
        for gid in list(referenced.keys()):
            if gid in raw and gid not in referenced[gid]:
                referenced[gid].append(f"{label}: {item.get('name', item.get('id'))}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    cfg = load_config(args.config)
    client = build_client(cfg)

    grp_path = client.resolve_endpoint(GROUPS_PATH, ["network", "group"])
    all_groups = client.get_all_pages(grp_path)
    print(f"{len(all_groups)} network groups on the device.")

    referenced = {g["id"]: [] for g in all_groups}

    # A group can be a member of another group -- self-scan excludes each
    # group's own definition (a group always "contains itself" in the raw
    # JSON dump otherwise).
    for g in all_groups:
        raw = json.dumps({k: v for k, v in g.items() if k != "id"})
        for other in all_groups:
            if other["id"] == g["id"]:
                continue
            if other["id"] in raw:
                referenced[other["id"]].append(f"network group: {g.get('name')}")

    collect_referenced_ids(client, client.resolve_endpoint(S2SVPN_PATH, ["s2s", "connection"]),
                            "S2S VPN profile", referenced)
    collect_referenced_ids(client, client.resolve_endpoint(HTTP_ACCESS_LISTS_PATH, ["http", "access"]),
                            "HTTPS mgmt access list", referenced)
    collect_referenced_ids(client, client.resolve_endpoint(SSH_ACCESS_LISTS_PATH, ["ssh", "access"]),
                            "SSH mgmt access list", referenced)
    collect_referenced_ids(client, client.resolve_endpoint(MANAGEMENT_ACCESS_PATH, ["management", "access"]),
                            "data-interface mgmt access", referenced)
    collect_referenced_ids(client, client.resolve_endpoint(SNMP_HOSTS_PATH, ["snmp", "host"]),
                            "SNMP host", referenced)
    collect_referenced_ids(client, client.resolve_endpoint(ICMP_PATH, ["icmp"]),
                            "ICMP rule", referenced)

    auto_nat_policies_path = client.resolve_endpoint(AUTO_NAT_POLICIES_PATH, ["object", "nat", "polic"])
    try:
        auto_nat_policies = client.get_all_pages(auto_nat_policies_path)
    except FdmApiError as e:
        print(f"  ! could not list auto-NAT policies: {e}")
        auto_nat_policies = []
    for pol in auto_nat_policies:
        collect_referenced_ids(client, f"{auto_nat_policies_path}/{pol['id']}/objectnatrules",
                                f"auto NAT rule ({pol.get('name')})", referenced)

    manual_nat_policies_path = client.resolve_endpoint(MANUAL_NAT_POLICIES_PATH, ["manual", "nat", "polic"])
    try:
        manual_nat_policies = client.get_all_pages(manual_nat_policies_path)
    except FdmApiError as e:
        print(f"  ! could not list manual NAT policies: {e}")
        manual_nat_policies = []
    for pol in manual_nat_policies:
        collect_referenced_ids(client, f"{manual_nat_policies_path}/{pol['id']}/manualnatrules",
                                f"manual NAT rule ({pol.get('name')})", referenced)

    access_policies_path = client.resolve_endpoint(ACCESS_POLICIES_PATH, ["access", "polic"])
    try:
        acps = client.get_all_pages(access_policies_path)
    except FdmApiError as e:
        print(f"  ! could not list access policies: {e}")
        acps = []
    for pol in acps:
        collect_referenced_ids(client, f"{access_policies_path}/{pol['id']}/accessrules",
                                f"access rule ({pol.get('name')})", referenced)

    vr_path = client.resolve_endpoint(VIRTUAL_ROUTERS_PATH, ["virtualrouter"])
    try:
        vrs = client.get_all_pages(vr_path)
    except FdmApiError as e:
        print(f"  ! could not list virtual routers: {e}")
        vrs = []
    for vr in vrs:
        collect_referenced_ids(client, f"{vr_path}/{vr['id']}/staticrouteentries",
                                f"static route ({vr.get('name')})", referenced)

    unused = [g for g in all_groups if not referenced[g["id"]]]
    used = [g for g in all_groups if referenced[g["id"]]]
    print(f"\n{len(used)} group(s) referenced somewhere, {len(unused)} group(s) not "
          f"referenced anywhere scanned.")

    for g in sorted(unused, key=lambda x: x.get("name", "")):
        print(f"  {g.get('name')} (id={g['id']})")

    if args.out:
        with open(args.out, "w") as f:
            json.dump([{"id": g["id"], "name": g.get("name")} for g in unused], f, indent=2)
        print(f"\nWrote {args.out}")


if __name__ == "__main__":
    main()
