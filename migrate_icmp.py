#!/usr/bin/env python3
"""
Push ASA's ICMP control-plane access list (`icmp permit`/`icmp deny`,
parsed by parse_asa_config.py) into FTD via the FDM REST API. This is
unrelated to through-traffic ACLs -- it's ASA's control over which
hosts/networks may send ICMP to the firewall's own interfaces.

*** UNVERIFIED -- no real API Explorer data behind this at all ***
Endpoint (`ICMP_PATH` below) and every field name are a structural guess,
modeled on the pattern confirmed for this toolkit's other device settings
(DNS/SNMP/NTP each live under `devicesettings/default/...`) and on
`migrate_access_control.py`'s confirmed `accessrule` shape (zone + network
references, since ASA interfaces map to FTD security zones, not raw
interfaces, in every confirmed rule-like object so far). Neither the
endpoint nor the body fields have been checked against a live device.
Share a real GET from API Explorer (search "icmp") the same way every
confirmed endpoint in this toolkit was found, and this can be corrected.

**Rule order matters and is not fixed by this script.** ASA (and
presumably whatever FTD equivalent exists) evaluates these top-to-bottom,
first match wins. `parser/asa_parser.py`'s parse_icmp_control() preserves
the original order but does not detect or fix a real, plausible issue:
a `deny any <interface>` entry followed by more `permit` entries for the
same interface makes those later entries unreachable on the ASA already.
This script prints a warning for any such unreachable entry per interface
and still creates it (in case the ASA behavior is intentional and being
faithfully carried over is what you want) -- it's your call, not a bug to
silently work around.

Usage:
    python migrate_icmp.py --config config.yaml --in-dir parsed/
"""
import argparse
import json
import os

from common.fdm_client import load_config, build_client, FdmApiError
from common.net_helpers import get_or_create_network, NETWORKS_PATH

ICMP_PATH = "devicesettings/default/icmp"  # guess, unverified -- see docstring
INTERFACES_PATH = "devices/default/interfaces"
SECURITY_ZONES_PATH = "object/securityzones"


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


def flag_unreachable_entries(entries):
    """Print a warning for any entry that can never match because an
    earlier `deny any` on the same interface already caught everything."""
    denied_any_interfaces = set()
    for e in entries:
        if e["interface"] in denied_any_interfaces:
            print(f"  ! '{e['action']} {e.get('value') or 'any'}' on '{e['interface']}' is "
                  f"unreachable -- an earlier 'DENY any' on the same interface already "
                  f"matches everything. Migrating it anyway; reorder or remove by hand in "
                  f"FDM if this was accidental on the ASA.")
        if e["action"] == "DENY" and e["subType"] == "ANY":
            denied_any_interfaces.add(e["interface"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--in-dir", default="parsed")
    args = ap.parse_args()

    cfg = load_config(args.config)
    skip_existing = cfg.get("options", {}).get("skip_existing", True)
    interface_map = cfg.get("interface_map", {})
    client = build_client(cfg)

    with open(os.path.join(args.in_dir, "icmp_control.json")) as f:
        entries = json.load(f)["entries"]

    print(f"Processing {len(entries)} ICMP control-plane entry/entries...")
    flag_unreachable_entries(entries)

    path = client.resolve_endpoint(ICMP_PATH, ["icmp"])
    net_path = client.resolve_endpoint(NETWORKS_PATH, ["network"])
    iface_path = client.resolve_endpoint(INTERFACES_PATH, ["interfaces"])
    zone_path = client.resolve_endpoint(SECURITY_ZONES_PATH, ["security", "zone"])

    created = 0
    for i, entry in enumerate(entries):
        ftd_iface_name = interface_map.get(entry["interface"])
        if not ftd_iface_name:
            print(f"  ! no interface_map entry for ASA nameif '{entry['interface']}', "
                  f"skipping: {entry['action']} {entry.get('value') or 'any'}")
            continue
        zone_ref = resolve_zone(client, iface_path, zone_path, ftd_iface_name)

        network_refs = []
        if entry["subType"] != "ANY":
            try:
                network_refs = [get_or_create_network(
                    client, net_path, entry["value"], entry["subType"], skip_existing)]
            except FdmApiError as e:
                print(f"  ! could not resolve network '{entry['value']}' for entry on "
                      f"'{entry['interface']}': {e}, skipping")
                continue

        body = {
            "name": f"ICMP_{i + 1}",
            "action": entry["action"],
            "sourceNetworks": network_refs,
            "sourceZones": [zone_ref] if zone_ref else [],
            "type": "icmpaccessrule",
        }
        try:
            client.create_or_reuse(path, body, skip_existing)
            created += 1
        except FdmApiError as e:
            print(f"  ! failed to create ICMP entry {i + 1} "
                  f"({entry['action']} {entry.get('value') or 'any'} on {entry['interface']}): "
                  f"{e}\n    Compare the request above against "
                  f"https://{client.host}/#/api-explorer and fix the body fields in "
                  f"migrate_icmp.py, then re-run.")
    print(f"ICMP control-plane: processed {len(entries)}, created/reused {created}.")

    if not cfg.get("options", {}).get("dry_run", True):
        deploy = input("Deploy these changes to the device now? [y/N] ").strip().lower()
        if deploy == "y":
            client.deploy()
        else:
            print("Skipped deploy -- ICMP entries are staged as pending changes in FDM.")


if __name__ == "__main__":
    main()
