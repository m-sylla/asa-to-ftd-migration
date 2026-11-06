#!/usr/bin/env python3
"""
One-off: verify the live manual NAT rules on FTD against the current ASA
parse, by actual values (source/destination real+mapped object names) --
not by name, since migrate_nat.py names rules `NAT_{position}` (a plain
index into whatever list it iterated that run) and its skip_existing dedup
only matches by that name. A rerun with a different subset/order (e.g. an
--only-names-scoped run) can collide with an unrelated rule that happens to
land at the same position, causing skip_existing to silently "reuse" the
wrong object while reporting success -- confirmed live via a direct test
against peer Hst-10.10.22.115's rule.

This script does not create, delete, or rename anything. It reports:
  - live rules that match an expected (non-identity) ASA NAT rule by value
  - live rules that do NOT match any expected rule (misattributed/stale --
    likely from a differently-scoped run's positional-name collision, or a
    rule for something no longer in the current ASA config)
  - expected rules with no live counterpart (genuinely never created)

Usage:
    python verify_nat_rules_live.py --config config.yaml --in-dir parsed/
"""
import argparse
import json
import os

from common.fdm_client import load_config, build_client, FdmApiError

MANUAL_NAT_POLICIES_PATH = "policy/manualnatpolicies"


def resolve_manual_nat_rules_path(client):
    policies_path = client.resolve_endpoint(MANUAL_NAT_POLICIES_PATH, ["manual", "nat", "polic"])
    policies = client.get_all_pages(policies_path)
    before_auto = next((p for p in policies if p.get("afterAuto") is False), None)
    if not before_auto:
        raise SystemExit(f"Could not find the before-auto manual NAT policy among: "
                          f"{[p.get('name') for p in policies]}")
    return before_auto, f"{policies_path}/{before_auto['id']}/manualnatrules"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--in-dir", default="parsed")
    args = ap.parse_args()

    cfg = load_config(args.config)
    client = build_client(cfg)
    if client.dry_run:
        raise SystemExit("This reads live device state -- set options.dry_run: false to run it "
                          "(it makes no changes either way).")

    with open(os.path.join(args.in_dir, "nat_exemptions.json"), encoding="utf-8") as f:
        parsed_rules = json.load(f)["rules"]
    expected = [r for r in parsed_rules if not r["is_identity"]]
    print(f"{len(expected)} non-identity manual NAT rule(s) expected from the current ASA parse.")

    def expected_key(r):
        return (r["source_real"], r["source_mapped"],
                r.get("destination_real"), r.get("destination_mapped"))

    expected_by_key = {expected_key(r): r for r in expected}

    policy, rules_path = resolve_manual_nat_rules_path(client)
    print(f"Live policy: {policy['name']} ({policy['id']})")
    live_items = client.get_all_pages(rules_path)
    print(f"{len(live_items)} manual NAT rule(s) live on the device.\n")

    matched_expected_keys = set()
    unmatched_live = []
    for item in live_items:
        full = client.get(f"{rules_path}/{item['id']}")
        src_real = full.get("originalSource", {}).get("name")
        src_mapped = full.get("translatedSource", {}).get("name") if full.get("translatedSource") else None
        dst_real = (full.get("originalDestination") or {}).get("name")
        dst_mapped = (full.get("translatedDestination") or {}).get("name")
        key = (src_real, src_mapped, dst_real, dst_mapped)
        if key in expected_by_key:
            matched_expected_keys.add(key)
        else:
            unmatched_live.append({
                "name": full.get("name"), "id": full["id"],
                "source_real": src_real, "source_mapped": src_mapped,
                "destination_real": dst_real, "destination_mapped": dst_mapped,
            })

    missing_expected = [r for k, r in expected_by_key.items() if k not in matched_expected_keys]

    print(f"CORRECT: {len(matched_expected_keys)}/{len(expected)} expected rule(s) found live "
          f"with matching values.\n")

    print(f"MISATTRIBUTED/STALE live rule(s) -- exist on the device but don't match any "
          f"current expected rule ({len(unmatched_live)}):")
    for u in unmatched_live:
        print(f"  {u['name']} (id={u['id']}): {u['source_real']} -> {u['source_mapped']}"
              f" | dest: {u['destination_real']} -> {u['destination_mapped']}")

    print(f"\nMISSING expected rule(s) -- not found live under any name ({len(missing_expected)}):")
    for r in missing_expected:
        print(f"  {r['raw']}")

    out_path = os.path.join(args.in_dir, "nat_rule_verification.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({
            "matched_count": len(matched_expected_keys),
            "expected_count": len(expected),
            "unmatched_live": unmatched_live,
            "missing_expected": missing_expected,
        }, f, indent=2, ensure_ascii=False)
    print(f"\nWrote {out_path}")


if __name__ == "__main__":
    main()
