#!/usr/bin/env python3
"""
Push ASA's HTTPS/ASDM management access list (`http server enable` /
`http <net> <mask> <interface>`, parsed by parse_asa_config.py) into FTD
via the FDM REST API -- which networks may reach the device's own
management interface (FDM's web UI, in FTD's case).

*** CONFIRMED against a live device -- corrected from the original guess ***
A live GET of `devicesettings/default/httpaccesslists` showed the real
shape, and it's structurally nothing like what was first guessed:
  - It's a **single global list** (`httpaccesslist`, GET-then-PUT singleton,
    same pattern as DNS's DataDNSSettings / SNMP's SNMPServerSettings /
    NTP's ntp settings) holding one `networkObjects` array of NetworkObject
    references -- **not** a flat collection of per-interface
    "managementaccessentry" items with `sourceZones`, as first modeled on
    migrate_icmp.py's pattern. There is no interface/zone field on this
    object at all.
  - This means ASA's `http <net> <mask> <interface>` per-interface scoping
    has **no equivalent on this object**. Every ASA entry (whichever
    interface it was on) just contributes a network to the one merged list.
    A live device confirmed this concretely: the ASA config had entries
    tagged `interface management` (e.g. `10.0.0.0/24`, an example subnet
    admins reach this device's own management IP from) alongside `interface
    inside` entries -- the original per-interface-zone-scoped guess would
    have SKIPPED the `management`-tagged entries entirely (no `management`
    key in `interface_map`), which would have silently dropped exactly the
    subnet admin access most likely comes from. Fixed: interface is now
    ignored entirely for this script: every entry is included.
  - FTD ships with this list defaulting to `any-ipv4` + `any-ipv6` (allow
    management HTTPS from anywhere). Replacing that with ASA's actual
    restricted list is a real security change with real lockout risk if the
    host you're managing the device from isn't in that list -- this script
    prints the full resulting allow-list before and after the PUT so you
    can check that before it's deployed.

Usage:
    python migrate_http_access.py --config config.yaml --in-dir parsed/
"""
import argparse
import json
import os

from common.fdm_client import load_config, build_client, FdmApiError
from common.net_helpers import get_or_create_network, classify_cidr_or_range, NETWORKS_PATH

HTTP_ACCESS_LISTS_PATH = "devicesettings/default/httpaccesslists"  # confirmed against a live device


def _mask_to_cidr_value(net, mask):
    """`(net, mask)` -> a value string usable with classify_cidr_or_range(),
    matching this toolkit's HOST/NETWORK convention (bare IP for a /32)."""
    if mask == "255.255.255.255":
        return f"{net}/32"
    octets = [int(o) for o in mask.split(".")]
    bits = "".join(f"{o:08b}" for o in octets)
    prefix = bits.count("1")
    return f"{net}/{prefix}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--in-dir", default="parsed")
    args = ap.parse_args()

    cfg = load_config(args.config)
    skip_existing = cfg.get("options", {}).get("skip_existing", True)
    client = build_client(cfg)

    with open(os.path.join(args.in_dir, "http_management.json")) as f:
        http_data = json.load(f)

    if not http_data.get("enabled"):
        print("ASA had `http server enable` off (or not set) -- nothing to push.")
        return
    entries = http_data.get("entries", [])
    print(f"Processing {len(entries)} HTTPS management access entry/entries "
          f"(ASA had `http server enable`)...")

    path = client.resolve_endpoint(HTTP_ACCESS_LISTS_PATH, ["http", "access"])
    net_path = client.resolve_endpoint(NETWORKS_PATH, ["network"])

    if client.dry_run:
        existing_items = [{"id": "dryrun-httpaccesslist", "name": "dryrun",
                            "networkObjects": [{"id": "dryrun-any-ipv4", "type": "networkobject",
                                                 "name": "any-ipv4"}]}]
    else:
        existing_items = client.get_all_pages(path)
        if not existing_items:
            print(f"  ! no httpaccesslist object found at {path} -- if this 404s, the path "
                  f"itself may be wrong for this FTD version; check /#/api-explorer")
            return
        if len(existing_items) > 1:
            print(f"  i found {len(existing_items)} httpaccesslist objects at {path}, using "
                  f"the first ({existing_items[0].get('name')}) -- a live device only ever "
                  f"had one; check FDM if this looks wrong")

    item = existing_items[0]
    current_names = [n.get("name") for n in item.get("networkObjects", [])]
    print(f"Current allow-list on the device: {current_names or '(empty)'}")

    resolved_refs, seen_ids = [], set()
    for entry in entries:
        cidr_value = _mask_to_cidr_value(entry["value"], entry["mask"])
        sub_type, value = classify_cidr_or_range(cidr_value)
        try:
            ref = get_or_create_network(client, net_path, value, sub_type, skip_existing)
        except FdmApiError as e:
            print(f"  ! could not resolve network '{cidr_value}' (ASA interface "
                  f"'{entry['interface']}'): {e}, skipping")
            continue
        if ref["id"] not in seen_ids:
            seen_ids.add(ref["id"])
            resolved_refs.append(ref)

    new_names = [f"{e['value']}/{e['mask']}" for e in entries]
    print(f"New allow-list ({len(resolved_refs)} unique network(s), replacing the current "
          f"list above): {new_names}")

    body = dict(item)
    body.pop("links", None)
    body["networkObjects"] = resolved_refs

    if client.dry_run:
        print(f"[DRY-RUN] PUT {path}/{item['id']}")
        print(json.dumps(body, indent=2))
    else:
        try:
            client.put(f"{path}/{item['id']}", body)
            print(f"  + updated httpaccesslist {item['id']} with {len(resolved_refs)} "
                  f"network(s)")
        except FdmApiError as e:
            print(f"  ! failed to update httpaccesslist {item['id']}: {e}\n"
                  f"    Compare the request above against "
                  f"https://{client.host}/#/api-explorer and fix the body fields in "
                  f"migrate_http_access.py, then re-run.")
            return

    print(f"HTTPS management access: replaced device's allow-list with "
          f"{len(resolved_refs)} network(s) from {len(entries)} ASA entry/entries.")

    if not cfg.get("options", {}).get("dry_run", True):
        deploy = input("Deploy these changes to the device now? [y/N] ").strip().lower()
        if deploy == "y":
            client.deploy()
        else:
            print("Skipped deploy -- HTTPS management access changes are staged as pending "
                  "changes in FDM.")


if __name__ == "__main__":
    main()
