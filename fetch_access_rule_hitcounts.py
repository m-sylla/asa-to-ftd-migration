#!/usr/bin/env python3
"""
Read hit counts for Access Control Policy rules on the live FTD -- mainly
useful for confirming the VPN_<peer>_IN/_OUT rules migrate_access_control.py
creates are actually passing traffic, not just present.

Endpoint and response shape confirmed live:
`policy/accesspolicies/{policyId}/operational/hitcounts` -- paginated like
every other collection here (items/paging with limit/offset), each item
shaped like {"hitCount": N, "rule": {"name", "ruleId", "id", ...},
"firstHitTimeStamp", "lastHitTimeStamp", "lastFetchTimeStamp"}. Read-only;
this script changes nothing on the device.

Usage:
    python fetch_access_rule_hitcounts.py --config config.yaml
    python fetch_access_rule_hitcounts.py --config config.yaml --name-prefix VPN_
    python fetch_access_rule_hitcounts.py --config config.yaml --out hitcounts.json
"""
import argparse
import json

from common.fdm_client import load_config, build_client, FdmApiError

ACCESS_POLICIES_PATH = "policy/accesspolicies"  # confirmed against a live device


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--name-prefix", default=None,
                     help="Only show rules whose name starts with this (e.g. VPN_ to scope "
                          "to the rules migrate_access_control.py created)")
    ap.add_argument("--out", default=None, help="Optional path to write the full result as JSON")
    args = ap.parse_args()

    cfg = load_config(args.config)
    client = build_client(cfg)
    if client.dry_run:
        raise SystemExit("This reads live device state -- set options.dry_run: false in "
                          "config.yaml to run it (it makes no changes either way).")

    policies_path = client.resolve_endpoint(ACCESS_POLICIES_PATH, ["access", "polic"])
    policies = client.get_all_pages(policies_path)

    rows = []
    for policy in policies:
        try:
            hitcounts = client.get_all_pages(
                f"{policies_path}/{policy['id']}/operational/hitcounts")
        except FdmApiError as e:
            print(f"  ! could not read hit counts for policy '{policy.get('name')}': {e}")
            continue
        for entry in hitcounts:
            rule = entry.get("rule", {})
            name = rule.get("name", "")
            if args.name_prefix and not name.startswith(args.name_prefix):
                continue
            rows.append({
                "policy": policy.get("name"),
                "name": name,
                "ruleId": rule.get("ruleId"),
                "id": rule.get("id"),
                "hitCount": entry.get("hitCount", 0),
                "firstHitTimeStamp": entry.get("firstHitTimeStamp") or None,
                "lastHitTimeStamp": entry.get("lastHitTimeStamp") or None,
            })

    rows.sort(key=lambda r: (r["policy"], -r["hitCount"], r["name"]))
    print(f"{len(rows)} rule(s) with hit-count data"
          f"{f' (name starts with {args.name_prefix!r})' if args.name_prefix else ''}:\n")
    for r in rows:
        print(f"  {r['hitCount']:>10}  {r['name']}  (policy={r['policy']})")

    zero_hit = [r for r in rows if r["hitCount"] == 0]
    print(f"\n{len(zero_hit)}/{len(rows)} rule(s) with zero hits.")
    for r in zero_hit:
        print(f"  {r['name']}")

    if args.out:
        with open(args.out, "w") as f:
            json.dump(rows, f, indent=2)
        print(f"\nWrote {args.out}")


if __name__ == "__main__":
    main()
