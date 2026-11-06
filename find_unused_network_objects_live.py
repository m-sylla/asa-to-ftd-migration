#!/usr/bin/env python3
"""
One-off: find network objects that exist on the live FTD but aren't
referenced anywhere on the device -- not in a network group, S2S VPN
profile, access rule, manual/auto NAT rule, static route, SNMP host, or any
of the HTTPS/SSH/data-interface management access lists.

This is the live-device counterpart to find_unused_objects.py (which
analyzes the ASA config text only). The two can disagree -- an object the
ASA config references is still "used" there even if the FTD-side tunnel
using it failed to create (DES-only tunnel, a PSK with an invalid character,
etc.), so it can show up as unused here but not in the ASA-side report, or
vice versa (an object referenced only by something this script doesn't scan,
e.g. remote-access VPN, isn't covered). Reports only -- does not delete
anything.

Usage:
    python find_unused_network_objects_live.py --config config.yaml
"""
import argparse
import json

from common.fdm_client import load_config, build_client, FdmApiError

NETWORKS_PATH = "object/networks"
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
        for net_id in list(referenced.keys()):
            if net_id in raw and net_id not in referenced[net_id]:
                referenced[net_id].append(f"{label}: {item.get('name', item.get('id'))}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--out", default=None, help="Optional path to write the unused-object list as JSON")
    args = ap.parse_args()

    cfg = load_config(args.config)
    client = build_client(cfg)

    net_path = client.resolve_endpoint(NETWORKS_PATH, ["network"])
    all_objects = client.get_all_pages(net_path)
    print(f"{len(all_objects)} network objects on the device.")

    referenced = {o["id"]: [] for o in all_objects}

    collect_referenced_ids(client, client.resolve_endpoint(GROUPS_PATH, ["network", "group"]),
                            "network group", referenced)
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

    icmp_path = client.resolve_endpoint(ICMP_PATH, ["icmp"])
    collect_referenced_ids(client, icmp_path, "ICMP rule", referenced)

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

    unused = [o for o in all_objects if not referenced[o["id"]]]
    used = [o for o in all_objects if referenced[o["id"]]]
    print(f"\n{len(used)} object(s) referenced somewhere, {len(unused)} object(s) not "
          f"referenced anywhere scanned.")

    protected = {"any-ipv4", "any-ipv6"}
    unused = [o for o in unused if o.get("name") not in protected]
    print(f"{len(unused)} after excluding FTD built-ins ({sorted(protected)}).")

    for o in sorted(unused, key=lambda x: x.get("name", "")):
        print(f"  {o.get('name')} (id={o['id']}, value={o.get('value')})")

    if args.out:
        with open(args.out, "w") as f:
            json.dump([{"id": o["id"], "name": o.get("name"), "value": o.get("value")}
                       for o in unused], f, indent=2)
        print(f"\nWrote {args.out}")


if __name__ == "__main__":
    main()
