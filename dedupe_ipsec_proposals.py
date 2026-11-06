#!/usr/bin/env python3
"""
One-off: consolidate duplicate-value IKEv1/IKEv2 IPsec proposals on a live
FTD. migrate_s2s_vpn.py creates one proposal per tunnel, named
ASA_TS_<crypto_map>_<seq> / ASA_PROP_<crypto_map>_<seq> -- so two tunnels
using the identical encryption/authentication combination get two separate,
identically-configured proposal objects instead of sharing one. Confirmed
live: FTD enforces a platform limit of 20 ipsec-proposals -- deploy failed
with "the maximum proposal limit of 20 was exceeded" on a device with 41
IKEv2 proposals backing only ~3 distinct crypto combinations (26 tunnels
shared one combination alone).

Unlike the IKEv2-*policy* duplicates (global, unreferenced -- disabling was
enough), proposals ARE referenced per-tunnel via each S2S connection
profile's ikev1Proposals/ikev2Proposals list, so fixing this needs a
repoint-then-delete, same shape as the network-object dedupe:
  1. Group live proposals by value (encryptionMethod/authenticationMethod
     for IKEv1; encryptionTypes/integrityTypes for IKEv2).
  2. Per group, pick a canonical survivor -- an FTD built-in default if one
     is in the group (never delete those), else the lowest tunnel-numbered
     one.
  3. Scan every S2S connection profile's proposal list for a reference to a
     non-canonical duplicate; if found, swap it for the canonical id and PUT.
  4. Delete the now-unreferenced duplicates.

Usage:
    python dedupe_ipsec_proposals.py --config config.yaml            # preview
    python dedupe_ipsec_proposals.py --config config.yaml --apply    # do it
"""
import argparse
from collections import defaultdict

from common.fdm_client import load_config, build_client, FdmApiError

IKEV1_PROPOSAL_PATH = "object/ikev1proposals"
IKEV2_PROPOSAL_PATH = "object/ikev2proposals"
S2SVPN_PATH = "devices/default/s2sconnectionprofiles"


def _is_builtin(name):
    return not (name.startswith("ASA_TS_") or name.startswith("ASA_PROP_"))


def _group_by_value(items, value_keys):
    by_value = defaultdict(list)
    for item in items:
        key = tuple(tuple(v) if isinstance(v, list) else v
                     for v in (item.get(k) for k in value_keys))
        by_value[key].append(item)
    return by_value


def _pick_canonical(group):
    builtins = [g for g in group if _is_builtin(g.get("name", ""))]
    if builtins:
        return builtins[0]
    return min(group, key=lambda g: g.get("name", ""))


def dedupe(client, path, value_keys, label, s2s_profiles, s2s_path, field, apply):
    items = client.get_all_pages(path)
    by_value = _group_by_value(items, value_keys)
    dup_groups = {k: v for k, v in by_value.items() if len(v) > 1}

    id_map = {}  # dup id -> (canonical id, canonical name)
    for key, group in dup_groups.items():
        canonical = _pick_canonical(group)
        for g in group:
            if g["id"] != canonical["id"]:
                id_map[g["id"]] = (canonical["id"], canonical["name"])
        print(f"{label} group {key}: keeping '{canonical['name']}', "
              f"dropping {[g['name'] for g in group if g['id'] != canonical['id']]}")

    if not id_map:
        print(f"No duplicate {label} found.")
        return

    touched = 0
    for profile in s2s_profiles:
        refs = profile.get(field) or []
        changed = False
        new_refs = []
        for ref in refs:
            if ref.get("id") in id_map:
                new_id, new_name = id_map[ref["id"]]
                new_refs.append({"id": new_id, "type": ref.get("type")})
                changed = True
            else:
                new_refs.append(ref)
        if not changed:
            continue
        touched += 1
        if apply:
            body = dict(profile)
            body.pop("links", None)
            body[field] = new_refs
            try:
                client.put(f"{s2s_path}/{profile['id']}", body)
                print(f"  + repointed {profile.get('name')} ({field})")
            except FdmApiError as e:
                print(f"  ! failed to repoint {profile.get('name')}: {e}")
        else:
            print(f"  would repoint {profile.get('name')} ({field})")
    print(f"{'Repointed' if apply else 'Would repoint'} {touched} S2S profile(s) referencing "
          f"duplicate {label}.")

    if not apply:
        print(f"Preview only -- {len(id_map)} duplicate {label} would be deleted after "
              f"repointing.\n")
        return

    deleted = 0
    for dup_id, (canonical_id, canonical_name) in id_map.items():
        try:
            client.delete(f"{path}/{dup_id}")
            deleted += 1
        except FdmApiError as e:
            print(f"  ! failed to delete duplicate {label} (id={dup_id}): {e}")
    print(f"Deleted {deleted}/{len(id_map)} duplicate {label}.\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    cfg = load_config(args.config)
    client = build_client(cfg)

    s2s_path = client.resolve_endpoint(S2SVPN_PATH, ["s2s", "connection"])
    s2s_profiles = client.get_all_pages(s2s_path)

    ikev1_path = client.resolve_endpoint(IKEV1_PROPOSAL_PATH, ["ikev1", "proposal"])
    ikev2_path = client.resolve_endpoint(IKEV2_PROPOSAL_PATH, ["ikev2", "proposal"])

    dedupe(client, ikev1_path, ("encryptionMethod", "authenticationMethod"),
           "IKEv1 proposals", s2s_profiles, s2s_path, "ikev1Proposals", args.apply)
    dedupe(client, ikev2_path, ("encryptionTypes", "integrityTypes"),
           "IKEv2 proposals", s2s_profiles, s2s_path, "ikev2Proposals", args.apply)


if __name__ == "__main__":
    main()
