#!/usr/bin/env python3
"""
Push ASA network objects and object-groups (parsed by parse_asa_config.py)
into FTD via the FDM REST API as NetworkObject / NetworkObjectGroup.

Usage:
    python migrate_network_objects.py --config config.yaml --in-dir parsed/

Writes parsed/objects_map.json: {"<asa-name>": {"id": "...", "type": "networkobject|networkobjectgroup"}}
which migrate_routes.py and migrate_s2s_vpn.py read to resolve references.

ASA "range" objects have no direct FTD equivalent field-for-field but FDM's
NetworkObject supports subType RANGE the same way, so those pass through
unchanged. FQDN objects default to IPV4_ONLY resolution (ASA doesn't
distinguish at the object level either).
"""
import argparse
import json
import os

from common.fdm_client import load_config, build_client, FdmApiError

NETWORKS_PATH = "object/networks"
GROUPS_PATH = "object/networkgroups"


def push_objects(client, objects, skip_existing):
    name_to_ref = {}
    path = client.resolve_endpoint(NETWORKS_PATH, ["network"])
    for name, obj in objects.items():
        body = {
            "name": name,
            "description": obj.get("description", "")[:200],
            "subType": obj["subType"],
            "value": obj["value"],
            "type": "networkobject",
        }
        if obj["subType"] == "FQDN":
            body["dnsResolution"] = "IPV4_ONLY"
        try:
            created = client.create_or_reuse(path, body, skip_existing)
            name_to_ref[name] = {"id": created["id"], "type": "networkobject"}
        except FdmApiError as e:
            print(f"  ! failed to create object '{name}': {e}")
    return name_to_ref


def _literal_object_name(group_name, idx, literal):
    tag = literal["value"].replace("/", "_").replace(".", "-")
    return f"{group_name}_LIT{idx}_{tag}"[:64]


def push_groups(client, groups, name_to_ref, skip_existing):
    path = client.resolve_endpoint(GROUPS_PATH, ["network", "group"])
    net_path = client.resolve_endpoint(NETWORKS_PATH, ["network"])
    remaining = dict(groups)
    made_progress = True
    while remaining and made_progress:
        made_progress = False
        for name in list(remaining.keys()):
            grp = remaining[name]
            deps = [m for m in grp["members"] if m in groups]
            if any(d not in name_to_ref for d in deps):
                continue  # a dependency group hasn't been created yet
            member_refs = []
            unresolved = []
            for m in grp["members"]:
                if m in name_to_ref:
                    member_refs.append(name_to_ref[m])
                else:
                    unresolved.append(m)
            for i, lit in enumerate(grp["literals"]):
                lit_name = _literal_object_name(name, i, lit)
                lit_body = {
                    "name": lit_name, "description": "auto-created from inline group literal",
                    "subType": lit["subType"], "value": lit["value"], "type": "networkobject",
                }
                try:
                    created = client.create_or_reuse(net_path, lit_body, skip_existing)
                    member_refs.append({"id": created["id"], "type": "networkobject"})
                except FdmApiError as e:
                    print(f"  ! failed to create literal object for group '{name}': {e}")
            if unresolved:
                print(f"  ! group '{name}' has unresolved member(s) {unresolved}, "
                      f"creating with the members that did resolve")
            body = {
                "name": name,
                "description": grp.get("description", "")[:200],
                "objects": member_refs,
                "type": "networkobjectgroup",
            }
            try:
                created = client.create_or_reuse(path, body, skip_existing)
                name_to_ref[name] = {"id": created["id"], "type": "networkobjectgroup"}
            except FdmApiError as e:
                print(f"  ! failed to create group '{name}': {e}")
            del remaining[name]
            made_progress = True
    if remaining:
        print(f"  ! could not resolve group dependency order for: {list(remaining.keys())} "
              f"(likely a circular group-object reference)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--in-dir", default="parsed")
    args = ap.parse_args()

    cfg = load_config(args.config)
    skip_existing = cfg.get("options", {}).get("skip_existing", True)
    client = build_client(cfg)

    with open(os.path.join(args.in_dir, "network_objects.json")) as f:
        data = json.load(f)

    print(f"Creating {len(data['objects'])} network objects...")
    name_to_ref = push_objects(client, data["objects"], skip_existing)

    print(f"Creating {len(data['groups'])} network object-groups...")
    push_groups(client, data["groups"], name_to_ref, skip_existing)

    out_path = os.path.join(args.in_dir, "objects_map.json")
    with open(out_path, "w") as f:
        json.dump(name_to_ref, f, indent=2)
    print(f"Wrote {out_path} ({len(name_to_ref)} entries) for use by migrate_routes.py / migrate_s2s_vpn.py")

    if not cfg.get("options", {}).get("dry_run", True):
        deploy = input("Deploy these changes to the device now? [y/N] ").strip().lower()
        if deploy == "y":
            client.deploy()
        else:
            print("Skipped deploy -- objects are staged as pending changes in FDM.")


if __name__ == "__main__":
    main()
