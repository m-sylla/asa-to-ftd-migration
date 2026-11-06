#!/usr/bin/env python3
"""
Push ASA's HTTP/SSH management access lines onto FTD's *data interface*
management access -- a separate mechanism from the global Management-
interface allow-list handled by migrate_http_access.py / migrate_ssh_access.py.

*** CONFIRMED against a live device ***
A live GET of `devicesettings/default/managementaccess` returned one
`datainterfacemanagementaccess` item: `{networkInterface: <physicalinterface
ref>, protocols: ["HTTPS"], networkObjects: [...]}`. This is FDM's per-data-
interface "allow HTTPS/SSH management access on this interface, from these
networks" setting (the toggle+allow-list on each data interface's own
configuration page in FDM's UI) -- distinct from the global
httpaccesslists/sshaccesslists objects, which govern the dedicated
Management interface instead (confirmed by comparing the two live: the
global lists have no interface field at all, this one is keyed by interface).

ASA's `http`/`ssh <net> <mask> <interface>` lines where `<interface>` is an
actual data interface (resolved via config.yaml's `interface_map`) map onto
this object. Lines tagged with ASA's `management` interface do NOT belong
here; they're not in `interface_map` (nothing maps to it) and are already
handled by the global lists.

**FDM allows only ONE managementaccess rule per interface, covering every
enabled protocol with a single shared `networkObjects` list** -- confirmed
live: a second POST for the same interface (attempted with protocols
split into separate HTTPS/SSH items, the original design here) was
rejected outright: `422 duplicateInterfaceInList` -- "There is already a
management access list rule for this interface. Edit the existing rule."
So `protocols: ["HTTPS", "SSH"]` on one item, not two items, is required
when both are enabled on the same interface.

This creates a real modeling gap when ASA's per-protocol lists for the same
interface don't match -- confirmed on this device: ASA's HTTPS-on-`inside`
list had `192.168.1.0/24` that SSH-on-`inside`'s list didn't (every other
host was identical between the two). FDM cannot express "this network gets
HTTPS but not SSH" on one interface. Resolved by explicit decision (not a
default policy): **intersection** -- an interface's merged list is the set
of networks common to every protocol configured on it, computed from each
protocol's raw (value, mask) entries before resolving to NetworkObject refs.
This never grants a network more access than ASA gave it for any single
protocol; it only narrows a network that had asymmetric per-protocol access
down to the protocols it was actually granted everywhere. If your ASA data
has a similar asymmetry on a different interface, this script prints
exactly what's included/excluded so it stays auditable -- it is not
guaranteed to be the right call in every case, just the one confirmed
correct for this migration's actual data.

Existing items have no usable name field (FDM auto-names them with an
opaque numeric string, e.g. "-1316907067") -- matching against what already
exists is done by `networkInterface` id, not create_or_reuse()'s name-based
lookup.

Usage:
    python migrate_http_data_interface_access.py --config config.yaml --in-dir parsed/
"""
import argparse
import json
import os

from common.fdm_client import load_config, build_client, FdmApiError
from common.net_helpers import get_or_create_network, classify_cidr_or_range, NETWORKS_PATH

MANAGEMENT_ACCESS_PATH = "devicesettings/default/managementaccess"  # confirmed against a live device
INTERFACES_PATH = "devices/default/interfaces"


def _mask_to_cidr_value(net, mask):
    """`(net, mask)` -> a value string usable with classify_cidr_or_range(),
    matching this toolkit's HOST/NETWORK convention (bare IP for a /32)."""
    if mask == "255.255.255.255":
        return f"{net}/32"
    octets = [int(o) for o in mask.split(".")]
    bits = "".join(f"{o:08b}" for o in octets)
    prefix = bits.count("1")
    return f"{net}/{prefix}"


def find_interface(client, iface_path, logical_name):
    interfaces = client.get_all_pages(iface_path)
    for iface in interfaces:
        if iface.get("name") == logical_name or iface.get("hardwareName") == logical_name:
            return iface
    return None


def _group_by_iface(entries, iface_map):
    """ASA entries -> {ftd_iface_name: {(value, mask), ...}}, dropping any
    entry whose ASA interface isn't a data interface (e.g. `management`)."""
    by_iface = {}
    for entry in entries:
        ftd_name = iface_map.get(entry["interface"])
        if not ftd_name:
            continue
        by_iface.setdefault(ftd_name, set()).add((entry["value"], entry["mask"]))
    return by_iface


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--in-dir", default="parsed")
    args = ap.parse_args()

    cfg = load_config(args.config)
    skip_existing = cfg.get("options", {}).get("skip_existing", True)
    interface_map = cfg.get("interface_map", {})
    client = build_client(cfg)

    with open(os.path.join(args.in_dir, "http_management.json")) as f:
        http_entries = json.load(f).get("entries", [])
    with open(os.path.join(args.in_dir, "ssh_management.json")) as f:
        ssh_entries = json.load(f).get("entries", [])

    path = client.resolve_endpoint(MANAGEMENT_ACCESS_PATH, ["management", "access"])
    net_path = client.resolve_endpoint(NETWORKS_PATH, ["network"])
    iface_path = client.resolve_endpoint(INTERFACES_PATH, ["interfaces"])

    existing_items = [] if client.dry_run else client.get_all_pages(path)

    by_iface_http = _group_by_iface(http_entries, interface_map)
    by_iface_ssh = _group_by_iface(ssh_entries, interface_map)
    all_ifaces = set(by_iface_http) | set(by_iface_ssh)

    for ftd_name in sorted(all_ifaces):
        protocols = []
        per_protocol_sets = []
        if ftd_name in by_iface_http:
            protocols.append("HTTPS")
            per_protocol_sets.append(by_iface_http[ftd_name])
        if ftd_name in by_iface_ssh:
            protocols.append("SSH")
            per_protocol_sets.append(by_iface_ssh[ftd_name])

        merged = set.intersection(*per_protocol_sets)
        if len(per_protocol_sets) > 1:
            union = set.union(*per_protocol_sets)
            dropped = union - merged
            if dropped:
                print(f"'{ftd_name}': protocols {protocols} don't all agree on the same "
                      f"networks -- using the intersection. Dropped (not common to every "
                      f"protocol on this interface): {sorted(dropped)}")

        if client.dry_run:
            iface = {"id": f"dryrun-iface-{ftd_name}", "type": "physicalinterface"}
        else:
            iface = find_interface(client, iface_path, ftd_name)
            if not iface:
                print(f"  ! FTD interface '{ftd_name}' not found, skipping {protocols}")
                continue
        iface_ref = {"id": iface["id"], "type": iface.get("type", "physicalinterface")}

        resolved_refs, seen_ids = [], set()
        for value, mask in sorted(merged):
            cidr_value = _mask_to_cidr_value(value, mask)
            sub_type, net_value = classify_cidr_or_range(cidr_value)
            try:
                ref = get_or_create_network(client, net_path, net_value, sub_type, skip_existing)
            except FdmApiError as e:
                print(f"  ! could not resolve network '{cidr_value}' on '{ftd_name}': {e}, "
                      f"skipping")
                continue
            if ref["id"] not in seen_ids:
                seen_ids.add(ref["id"])
                resolved_refs.append(ref)

        names = [f"{v}/{m}" for v, m in sorted(merged)]
        print(f"'{ftd_name}' {protocols}: {len(resolved_refs)} unique network(s) -- {names}")

        existing = next((it for it in existing_items
                          if it.get("networkInterface", {}).get("id") == iface["id"]), None)

        if existing:
            body = dict(existing)
            body.pop("links", None)
            body["protocols"] = protocols
            body["networkObjects"] = resolved_refs
            target = f"{path}/{existing['id']}"
            action = "update"
        else:
            body = {
                "networkInterface": iface_ref,
                "protocols": protocols,
                "networkObjects": resolved_refs,
                "type": "datainterfacemanagementaccess",
            }
            target = path
            action = "create"

        if client.dry_run:
            print(f"[DRY-RUN] {'PUT' if action == 'update' else 'POST'} {target}")
            print(json.dumps(body, indent=2))
            continue

        try:
            if action == "update":
                client.put(target, body)
                print(f"  + updated data-interface access on '{ftd_name}' "
                      f"(id={existing['id']}, protocols={protocols})")
            else:
                created = client.post(target, body)
                print(f"  + created data-interface access on '{ftd_name}' "
                      f"(id={created.get('id')}, protocols={protocols})")
                existing_items.append(created)
        except FdmApiError as e:
            print(f"  ! failed to {action} data-interface access on '{ftd_name}': {e}\n"
                  f"    Compare against https://{client.host}/#/api-explorer and fix "
                  f"the body fields in migrate_data_interface_access.py, then re-run.")

    if not cfg.get("options", {}).get("dry_run", True):
        deploy = input("Deploy these changes to the device now? [y/N] ").strip().lower()
        if deploy == "y":
            client.deploy()
        else:
            print("Skipped deploy -- data-interface management access changes are staged as "
                  "pending changes in FDM.")


if __name__ == "__main__":
    main()
