#!/usr/bin/env python3
"""
Push ASA static `route` statements (parsed by parse_asa_config.py) into FTD
as StaticRouteEntry objects via the FDM REST API.

Usage:
    python migrate_routes.py --config config.yaml --in-dir parsed/

Requires config.yaml's `interface_map` to be filled in (ASA nameif -> FTD
logical interface name) -- ASA and FTD interface names/logical-name
assignments are independent of each other even on identical hardware, so
this can't be inferred automatically. Destination networks and gateway IPs
are turned into (or matched against existing) NetworkObjects; a 0.0.0.0/0
route reuses FTD's built-in "any-ipv4" object.

Static routes are not a flat collection: FDM scopes them under a virtual
router (confirmed against a live FTD 7.6.x box -- a route's real path is
devices/default/routing/virtualrouters/{vrId}/staticrouteentries). Each
interface belongs to exactly one virtual router; for a single-context ASA
there's normally just one ("Global"), but this resolves per-interface so it
also works if the device has more than one configured.
"""
import argparse
import json
import os
import re

from common.fdm_client import load_config, build_client, FdmApiError
from common.net_helpers import get_or_create_network, NETWORKS_PATH

VIRTUAL_ROUTERS_PATH = "devices/default/routing/virtualrouters"
INTERFACES_PATH = "devices/default/interfaces"


def find_interface_ref(client, iface_path, logical_name):
    interfaces = client.get_all_pages(iface_path)
    for iface in interfaces:
        if iface.get("name") == logical_name or iface.get("hardwareName") == logical_name:
            return {"id": iface["id"], "type": iface.get("type", "physicalinterface")}
    return None


def find_virtual_router_for_interface(client, vr_path, iface_id):
    routers = client.get_all_pages(vr_path)
    for vr in routers:
        if any(i["id"] == iface_id for i in vr.get("interfaces", [])):
            return vr
    for vr in routers:
        if vr.get("name") == "Global":
            print("  ! interface not found in any virtual router's interface list, "
                  "defaulting to 'Global'")
            return vr
    return routers[0] if routers else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--in-dir", default="parsed")
    args = ap.parse_args()

    cfg = load_config(args.config)
    skip_existing = cfg.get("options", {}).get("skip_existing", True)
    iface_map = cfg.get("interface_map", {})
    client = build_client(cfg)

    with open(os.path.join(args.in_dir, "routes.json")) as f:
        routes = json.load(f)

    net_path = client.resolve_endpoint(NETWORKS_PATH, ["network"])
    vr_path = client.resolve_endpoint(VIRTUAL_ROUTERS_PATH, ["virtualrouter"])
    iface_path = client.resolve_endpoint(INTERFACES_PATH, ["interfaces"])

    # ftd_iface_name -> (iface_ref, staticrouteentries collection path for its virtual router)
    iface_cache = {}
    created = 0
    for r in routes:
        asa_iface = r["interface"]
        ftd_iface_name = iface_map.get(asa_iface)
        if not ftd_iface_name:
            print(f"  ! no interface_map entry for ASA nameif '{asa_iface}', skipping route "
                  f"{r['network']}/{r['prefix']} via {r['gateway']}")
            continue
        if ftd_iface_name not in iface_cache:
            if client.dry_run:
                iface_ref = {"id": f"dryrun-iface-{ftd_iface_name}", "type": "physicalinterface"}
                routes_path = f"{vr_path}/dryrun-vr/staticrouteentries"
                iface_cache[ftd_iface_name] = (iface_ref, routes_path)
            else:
                iface_ref = find_interface_ref(client, iface_path, ftd_iface_name)
                if not iface_ref:
                    print(f"  ! FTD interface '{ftd_iface_name}' not found on device, "
                          f"skipping routes on it")
                    iface_cache[ftd_iface_name] = (None, None)
                else:
                    vr = find_virtual_router_for_interface(client, vr_path, iface_ref["id"])
                    if not vr:
                        print(f"  ! could not find a virtual router for interface "
                              f"'{ftd_iface_name}', skipping routes on it")
                        iface_cache[ftd_iface_name] = (None, None)
                    else:
                        routes_path = f"{vr_path}/{vr['id']}/staticrouteentries"
                        iface_cache[ftd_iface_name] = (iface_ref, routes_path)
        iface_ref, routes_path = iface_cache[ftd_iface_name]
        if not iface_ref:
            continue

        is_default = r["network"] == "0.0.0.0" and r["prefix"] == "0"
        is_host_route = r["prefix"] == "32" and not is_default
        if is_default:
            net_value, net_sub_type = "0.0.0.0/0", "NETWORK"
        elif is_host_route:
            # FDM rejects a /32 CIDR under subType NETWORK ("Invalid subnet
            # mask") -- a single-address destination has to be subType HOST
            # with a bare IP instead.
            net_value, net_sub_type = r["network"], "HOST"
        else:
            net_value, net_sub_type = f"{r['network']}/{r['prefix']}", "NETWORK"
        try:
            net_ref = get_or_create_network(client, net_path, net_value, net_sub_type, skip_existing)
            gw_ref = get_or_create_network(client, net_path, r["gateway"], "HOST", skip_existing)
        except FdmApiError as e:
            print(f"  ! failed to resolve network/gateway object for route "
                  f"{net_value} via {r['gateway']} on {asa_iface}: {e}")
            continue

        name = f"route-{asa_iface}-{re.sub(r'[./]', '-', net_value)}"[:64]
        body = {
            "name": name,
            "iface": iface_ref,
            "networks": [net_ref],
            "gateway": gw_ref,
            "metricValue": r["metric"],
            "ipType": "IPv4",
            "type": "staticrouteentry",
        }
        try:
            client.create_or_reuse(routes_path, body, skip_existing)
            created += 1
        except FdmApiError as e:
            print(f"  ! failed to create route {name}: {e}")

    print(f"Processed {len(routes)} ASA route statements, created/reused {created} static routes.")

    if not client.dry_run:
        deploy = input("Deploy these changes to the device now? [y/N] ").strip().lower()
        if deploy == "y":
            client.deploy()
        else:
            print("Skipped deploy -- routes are staged as pending changes in FDM.")


if __name__ == "__main__":
    main()
