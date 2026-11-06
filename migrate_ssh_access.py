#!/usr/bin/env python3
"""
Push ASA's SSH management access list (`ssh <net-or-alias> <mask>
<interface>`, parsed by parse_asa_config.py) into FTD via the FDM REST API
-- which networks may reach the device's own management interface via SSH.

*** CONFIRMED against a live device ***
Modeled on migrate_http_access.py's confirmed shape (a single global
`networkObjects` list, no interface/zone field at all -- see that script's
docstring for the full story of how that was found). The analogy held
exactly for SSH: a live GET of `devicesettings/default/sshaccesslists`
returned one `sshaccesslist` item, same shape as `httpaccesslist`
(`networkObjects` defaulting to `any-ipv4`/`any-ipv6`).

Same lockout-risk caveat as HTTPS management access applies here, arguably
more so -- SSH is the fallback path if the web UI is ever unreachable. This
script REPLACES the device's current allow-list with ASA's, same as
migrate_http_access.py, and prints the full resulting allow-list before the
PUT so you can check your own access path is covered before deploying.

**Note**: ASA's `ssh` lines only covered the `inside` interface (no
`management`-tagged entries like HTTPS had) -- so unlike the HTTPS list,
this one won't include the `10.0.0.0/24` management subnet unless a
future ASA export adds an `ssh ... management` line for it. If you SSH into
this device from that subnet, add it to `parsed/ssh_management.json` (or an
`ssh` line in asa-config.txt) before running this, or you'll lose SSH
access from there specifically (HTTPS/web UI access from that subnet is
unaffected -- that's a separate list).

Usage:
    python migrate_ssh_access.py --config config.yaml --in-dir parsed/
"""
import argparse
import json
import os

from common.fdm_client import load_config, build_client, FdmApiError
from common.net_helpers import get_or_create_network, classify_cidr_or_range, NETWORKS_PATH

SSH_ACCESS_LISTS_PATH = "devicesettings/default/sshaccesslists"  # UNVERIFIED -- see docstring


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

    with open(os.path.join(args.in_dir, "ssh_management.json")) as f:
        ssh_data = json.load(f)

    entries = ssh_data.get("entries", [])
    if not entries:
        print("No `ssh <net> <mask> <interface>` lines found in the ASA config -- nothing to push.")
        return
    print(f"Processing {len(entries)} SSH management access entry/entries...")

    path = client.resolve_endpoint(SSH_ACCESS_LISTS_PATH, ["ssh", "access"])
    net_path = client.resolve_endpoint(NETWORKS_PATH, ["network"])

    if client.dry_run:
        existing_items = [{"id": "dryrun-sshaccesslist", "name": "dryrun",
                            "networkObjects": [{"id": "dryrun-any-ipv4", "type": "networkobject",
                                                 "name": "any-ipv4"}]}]
    else:
        existing_items = client.get_all_pages(path)
        if not existing_items:
            print(f"  ! no sshaccesslist object found at {path} -- this endpoint is an "
                  f"unverified guess (see docstring); if this 404s, get a live GET from "
                  f"/#/api-explorer and fix SSH_ACCESS_LISTS_PATH before retrying")
            return
        if len(existing_items) > 1:
            print(f"  i found {len(existing_items)} sshaccesslist objects at {path}, using "
                  f"the first ({existing_items[0].get('name')}) -- httpaccesslists only ever "
                  f"had one on a live device; check FDM if this looks wrong")

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
            print(f"  + updated sshaccesslist {item['id']} with {len(resolved_refs)} "
                  f"network(s)")
        except FdmApiError as e:
            print(f"  ! failed to update sshaccesslist {item['id']}: {e}\n"
                  f"    Compare the request above against "
                  f"https://{client.host}/#/api-explorer and fix the endpoint/body fields "
                  f"in migrate_ssh_access.py, then re-run.")
            return

    print(f"SSH management access: replaced device's allow-list with "
          f"{len(resolved_refs)} network(s) from {len(entries)} ASA entry/entries.")

    if not cfg.get("options", {}).get("dry_run", True):
        deploy = input("Deploy these changes to the device now? [y/N] ").strip().lower()
        if deploy == "y":
            client.deploy()
        else:
            print("Skipped deploy -- SSH management access changes are staged as pending "
                  "changes in FDM.")


if __name__ == "__main__":
    main()
