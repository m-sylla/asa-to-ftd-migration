#!/usr/bin/env python3
"""
Push ASA's general NAT/PAT translation rules to FTD -- everything NAT-related
that migrate_s2s_vpn.py's interfaceForNatExempt does NOT cover. Two ASA
constructs, both parsed by parse_asa_config.py:

  - Manual/twice NAT (`nat (if1,if2) source static|dynamic X Y [destination
    static|dynamic A B]`) that is NOT an identity/no-NAT rule (those are
    already handled via interfaceForNatExempt on the S2S VPN connection --
    see parsed/nat_exemptions.json's `is_identity` field). This script only
    migrates the ones where source/destination genuinely translate.
  - Auto-NAT / object NAT (`object network NAME` / `nat (real,mapped)
    static|dynamic <target>`), ASA's per-object translation -- typically
    general internet-bound dynamic PAT and simple static 1:1 translations.

Usage:
    python migrate_nat.py --config config.yaml --in-dir parsed/
    python migrate_nat.py --config config.yaml --only-names Ntw-Example-External,NAT_PartnerA-10.100.0.0,NAT_PartnerB_Internal --skip-auto-nat

*** Manual NAT is confirmed live; auto-NAT (object NAT) is still a guess ***
General NAT has more real variety than anything else in this toolkit
(dynamic PAT via the egress interface's own address vs. a pool object,
static 1:1, per-service/port translation) and this script only attempts the
common cases (see parser/asa_parser.py's module docstring for exclusions).

Given the blast radius of getting NAT wrong (unlike VPN-specific config,
general NAT/PAT affects most or all traffic through the device), strongly
consider:
  1. Running this only with dry_run: true first and reading every printed
     body carefully against your own knowledge of the required behavior.
  2. Reviewing NAT rule ORDER in FDM afterward. This script does not attempt
     to control where rules land relative to each other or to existing
     rules; NAT evaluation order changes what actually happens to a packet.

MANUAL NAT IS NOW CONFIRMED (auto-NAT / object NAT below is still a guess).
A live GET of an existing manual NAT rule (`InsideOutsideNatRule`, FTD's own
onboarding-wizard default) showed the real shape:
  - Endpoint is nested under a manual NAT *policy*, like access rules under
    an access policy: `policy/manualnatpolicies/{policyId}/manualnatrules`
    -- not the flat `devices/default/manualnats` first guessed.
  - `sourceInterface`/`destinationInterface` are physicalinterface
    references (confirmed, matches the original guess).
  - `originalSource`/`originalDestination`/`translatedSource`/
    `translatedDestination` are NetworkObject references, `null` when absent
    (confirmed).
  - PAT via the egress interface's own address is `interfaceInTranslatedSource:
    true` with `translatedSource: null` -- NOT an `interfaceIpv4` field as
    first guessed (that field doesn't exist). The mirror field for a NAT'd
    *destination* being the ingress interface's own address is
    `interfaceInOriginalDestination` (not needed by any rule this toolkit's
    parser produces, since ASA's "interface" keyword only appears on the
    mapped side in what's parsed here, but included for completeness).
  - `noProxyArp`, `routeLookup`, `unidirectional`, `enabled`, `dns`,
    `interfaceIPv6` are plain booleans (confirmed).
  - **`netToNet` must NOT be sent at all**, even though a GET echoes it back
    as `false`. A live POST setting it (for ASA's `net-to-net` keyword) was
    rejected outright: `422 natOtherOptionsNotSupported` -- "The following
    options are not supported and should not be selected in NAT rules:
    netToNet". FTD apparently infers network-vs-host translation semantics
    from the object types themselves rather than a client-set flag. This
    script no longer sends it.
  - `patOptions` is null unless using a PAT pool (not produced by anything
    this toolkit's parser emits -- ASA's manual NAT dynamic-PAT-via-object
    case here always uses a single object, not a pool).

Auto-NAT (object NAT) endpoint is now confirmed too (rule body fields below
remain unverified -- no real GET of an individual rule yet, only the policy
container):
  - Auto-NAT rules nest under a policy container exactly like manual NAT --
    `policy/objectnatpolicies/{policyId}/objectnatrules` -- not the flat
    `devices/default/objectnats` first guessed (confirmed 404 live). A live
    GET of `policy/objectnatpolicies` returned one `objectnatrulecontainer`
    named `NGFW-Auto-NAT-Policy`.
  - Unlike manual NAT there's no before/after-auto split to pick between --
    only one auto-NAT container exists, so `resolve_auto_nat_rules_path()`
    doesn't need the `afterAuto` disambiguation manual NAT's resolver does.
If you can share a GET of one existing auto-NAT *rule* (not just the policy
container) from `/#/api-explorer`, the remaining body fields (`natType`,
`originalNetwork`/`translatedNetwork`, `interfaceIpv4`, etc.) can be
confirmed the same way manual NAT's were.

One field is now confirmed wrong from a live POST: the body's `"type"` is
**`objectnatrule`**, not `autonatrule` as first guessed -- a live attempt
with `autonatrule` was rejected with `InvalidTypeIdException: Could not
resolve type id 'autonatrule' as a subtype of ObjectNatRule`. This matches
the naming already visible in the confirmed container endpoint
(`objectnatpolicies` / `objectnatrulecontainer`), not the ASA-terminology
"auto-NAT" this script's own variable/function names use internally.

Also fixed from that same run: `resolve_named_ref()` crashed (`AttributeError`
on `None.lstrip()`) for any auto-NAT rule whose mapped/translated target is a
literal IP rather than an object name, because it unconditionally checked
`grp_path` for a group match even when auto-NAT callers pass `grp_path=None`
(auto-NAT has no network-group concept) -- the group lookup is now skipped
when `grp_path` is falsy, letting the existing get_or_create_network()
literal-IP fallback in migrate_auto_nat() actually run.
"""
import argparse
import json
import os

from common.fdm_client import load_config, build_client, FdmApiError
from common.net_helpers import NETWORKS_PATH

GROUPS_PATH = "object/networkgroups"
MANUAL_NAT_POLICIES_PATH = "policy/manualnatpolicies"  # confirmed against a live device
AUTO_NAT_POLICIES_PATH = "policy/objectnatpolicies"    # confirmed against a live device
INTERFACES_PATH = "devices/default/interfaces"


def resolve_manual_nat_rules_path(client):
    """Manual NAT rules nest under a manual NAT policy, like access rules
    under an access policy -- confirmed live, see module docstring.

    Confirmed live: there are actually *two* manual NAT policies --
    `NGFW-Before-Auto-NAT-Policy` (`afterAuto: false`) and
    `NGFW-After-Auto-NAT-Policy` (`afterAuto: true`, holding FTD's own
    default `InsideOutsideNatRule`). ASA's plain `nat (if1,if2) ...` lines
    (no `after-auto` keyword) are Section-1/before-auto-NAT rules, so this
    picks the `afterAuto: false` policy specifically -- picking whichever
    policy the API happens to list first would be wrong (confirmed: it
    listed the after-auto one first)."""
    policies_path = client.resolve_endpoint(MANUAL_NAT_POLICIES_PATH, ["manual", "nat", "polic"])
    if client.dry_run:
        return f"{policies_path}/dryrun-policy/manualnatrules"
    policies = client.get_all_pages(policies_path)
    if not policies:
        raise FdmApiError(
            f"no manual NAT policy found at {policies_path} -- if this 404s, the path "
            f"itself is wrong, see the docstring's note on how this was confirmed.")
    before_auto = [p for p in policies if p.get("afterAuto") is False]
    if not before_auto:
        raise FdmApiError(
            f"could not find a manual NAT policy with afterAuto:false among {policies_path} "
            f"-- found: {[(p.get('name'), p.get('afterAuto')) for p in policies]}")
    return f"{policies_path}/{before_auto[0]['id']}/manualnatrules"


def resolve_auto_nat_rules_path(client):
    """Auto-NAT (object NAT) rules nest under a policy container too, exactly
    like manual NAT -- confirmed live via GET policy/objectnatpolicies, which
    returned a single objectnatrulecontainer named `NGFW-Auto-NAT-Policy`.
    Unlike manual NAT there's only ever one auto-NAT container (auto-NAT has
    no before/after-auto split -- that split is what the two *manual* NAT
    policies encode), so no afterAuto-style disambiguation is needed."""
    policies_path = client.resolve_endpoint(AUTO_NAT_POLICIES_PATH, ["object", "nat", "polic"])
    if client.dry_run:
        return f"{policies_path}/dryrun-policy/objectnatrules"
    policies = client.get_all_pages(policies_path)
    if not policies:
        raise FdmApiError(
            f"no auto-NAT policy found at {policies_path} -- if this 404s, the path itself "
            f"is wrong, see the docstring's note on how this was confirmed.")
    if len(policies) > 1:
        print(f"  i found {len(policies)} auto-NAT policies at {policies_path}, using the "
              f"first ({policies[0].get('name')}) -- confirmed live setups only ever had one, "
              f"so this hasn't been seen; check FDM if this looks wrong")
    return f"{policies_path}/{policies[0]['id']}/objectnatrules"


def find_interface_ref(client, iface_path, logical_name):
    interfaces = client.get_all_pages(iface_path)
    for iface in interfaces:
        if iface.get("name") == logical_name or iface.get("hardwareName") == logical_name:
            return {"id": iface["id"], "type": iface.get("type", "physicalinterface")}
    return None


def resolve_named_ref(client, net_path, grp_path, name):
    """Look up an ASA object/group name against what migrate_network_objects.py
    already created on FTD (same names are reused end to end)."""
    if not name:
        return None
    if client.dry_run:
        return {"id": f"dryrun-obj-{name}", "type": "networkobject"}
    if name == "any":
        obj = client.find_by_name(net_path, "any-ipv4")
        return {"id": obj["id"], "type": "networkobject"} if obj else None
    obj = client.find_by_name(net_path, name)
    if obj:
        return {"id": obj["id"], "type": "networkobject"}
    grp = client.find_by_name(grp_path, name) if grp_path else None
    if grp:
        return {"id": grp["id"], "type": "networkobjectgroup"}
    return None


def iface_ref_or_none(client, iface_path, iface_map, asa_iface, context):
    """Returns None (meaning "any"/unrestricted) for ASA's "any" interface
    keyword, otherwise resolves through interface_map like every other script."""
    if asa_iface == "any":
        return "ANY", None
    ftd_name = iface_map.get(asa_iface)
    if not ftd_name:
        return "MISSING", None
    if client.dry_run:
        return "OK", {"id": f"dryrun-iface-{ftd_name}", "type": "physicalinterface"}
    ref = find_interface_ref(client, iface_path, ftd_name)
    return ("OK", ref) if ref else ("MISSING", None)


def _rule_names(rule):
    return {rule.get("source_real"), rule.get("source_mapped"),
            rule.get("destination_real"), rule.get("destination_mapped")} - {None}


def _safe_name_part(name):
    return "".join(c if c.isalnum() else "-" for c in name)


def existing_manual_nat_values(client, path):
    """CONFIRMED live (2026-09-21, root-caused during a doc reconciliation
    against the FMC sibling project): this script used to name rules
    `NAT_{position}` -- a plain index into whatever list it iterated *that
    run* -- and rely on create_or_reuse()'s name-based skip_existing dedup.
    A differently-scoped run (e.g. --only-names against a subset) produces a
    different, shorter list, so the same position can land on a
    *completely different* rule than the one a prior run put there. Tested
    directly: `--only-names Hst-10.10.22.115` matched and silently "reused"
    an unrelated existing `NAT_1` (source `lyle`, nothing to do with
    Hst-10.10.22.115) purely because both runs happened to compute position
    1 -- no values were ever compared. Dedup now goes by the rule's actual
    values instead (one detail GET per existing rule, done once, not name),
    same fix already applied to the FMC sibling project's equivalent
    scripts after hitting the identical class of bug there."""
    values = set()
    for item in client.get_all_pages(path):
        full = client.get(f"{path}/{item['id']}")
        values.add((
            (full.get("originalSource") or {}).get("id"),
            (full.get("translatedSource") or {}).get("id"),
            full.get("interfaceInTranslatedSource", False),
            (full.get("originalDestination") or {}).get("id"),
            (full.get("translatedDestination") or {}).get("id"),
            (full.get("sourceInterface") or {}).get("id"),
            (full.get("destinationInterface") or {}).get("id"),
        ))
    return values


def migrate_manual_nat(client, net_path, grp_path, iface_path, iface_map, rules, skip_existing,
                        only_names=None):
    """`only_names`, if given, restricts migration to rules that reference at
    least one of these object/group names (source or destination, real or
    mapped) -- useful for scoping a live run to a known subset (e.g. the
    rules backing a specific set of VPN tunnels) before trusting the rest."""
    path = resolve_manual_nat_rules_path(client)
    print(f"Manual NAT endpoint resolved to: {path}")

    translating = [r for r in rules if not r["is_identity"]]
    if only_names:
        translating = [r for r in translating if _rule_names(r) & only_names]
    print(f"Migrating {len(translating)} manual NAT rule(s) that translate traffic "
          f"(identity/no-NAT rules were already handled via VPN NAT exemption)...")
    existing_values = set() if client.dry_run else existing_manual_nat_values(client, path)
    created = 0
    for rule in translating:
        real_status, real_iface_ref = iface_ref_or_none(
            client, iface_path, iface_map, rule["real_interface"], "real")
        mapped_status, mapped_iface_ref = iface_ref_or_none(
            client, iface_path, iface_map, rule["mapped_interface"], "mapped")
        if "MISSING" in (real_status, mapped_status):
            print(f"  ! no interface_map entry for '{rule['real_interface']}' and/or "
                  f"'{rule['mapped_interface']}', skipping: {rule['raw']}")
            continue

        source_real_ref = resolve_named_ref(client, net_path, grp_path, rule["source_real"])
        if not source_real_ref:
            print(f"  ! could not resolve source object '{rule['source_real']}' on FTD, "
                  f"skipping: {rule['raw']}")
            continue

        is_interface_pat = rule["source_mapped"].lower() == "interface"
        source_mapped_ref = (None if is_interface_pat else
                              resolve_named_ref(client, net_path, grp_path, rule["source_mapped"]))
        if not is_interface_pat and not source_mapped_ref:
            print(f"  ! could not resolve translated-source object '{rule['source_mapped']}' "
                  f"on FTD, skipping: {rule['raw']}")
            continue

        dest_real_ref = (resolve_named_ref(client, net_path, grp_path, rule["destination_real"])
                          if rule.get("destination_real") else None)
        dest_mapped_ref = (resolve_named_ref(client, net_path, grp_path, rule["destination_mapped"])
                            if rule.get("destination_mapped") else None)

        # Content-derived, not positional (see existing_manual_nat_values()'s
        # docstring for why positional NAT_{i} names were unsafe). Interfaces
        # included too, since two rules can otherwise share the same source/
        # destination objects and differ only by real/mapped interface.
        name_parts = [_safe_name_part(rule["real_interface"]), _safe_name_part(rule["source_real"])]
        if rule.get("destination_real"):
            name_parts.append(_safe_name_part(rule["destination_real"]))
        body = {
            "name": f"NAT_{'_'.join(name_parts)}"[:64],
            "type": "manualnatrule",
            "natType": "STATIC" if rule["source_kind"] == "static" else "DYNAMIC",
            "originalSource": source_real_ref,
            "noProxyArp": rule.get("no_proxy_arp", False),
            "routeLookup": rule.get("route_lookup", False),
            "unidirectional": rule.get("unidirectional", False),
            "enabled": True,
        }
        if real_iface_ref:
            body["sourceInterface"] = real_iface_ref
        if mapped_iface_ref:
            body["destinationInterface"] = mapped_iface_ref
        if is_interface_pat:
            body["interfaceInTranslatedSource"] = True
            body["translatedSource"] = None
        else:
            body["translatedSource"] = source_mapped_ref
        if dest_real_ref:
            body["originalDestination"] = dest_real_ref
            body["translatedDestination"] = dest_mapped_ref or dest_real_ref

        value_key = (
            source_real_ref.get("id"), (source_mapped_ref or {}).get("id"),
            body.get("interfaceInTranslatedSource", False),
            (dest_real_ref or {}).get("id"), (body.get("translatedDestination") or {}).get("id"),
            (real_iface_ref or {}).get("id"), (mapped_iface_ref or {}).get("id"),
        )
        if skip_existing and value_key in existing_values:
            print(f"  = '{body['name']}' already exists (matched by value, not name -- "
                  f"see existing_manual_nat_values()'s docstring), reusing")
            created += 1
            continue
        try:
            created_rule = client.post(path, body)
            existing_values.add(value_key)
            print(f"  + created '{body['name']}' (id={created_rule.get('id')})")
            created += 1
        except FdmApiError as e:
            print(f"  ! failed to create manual NAT rule for '{rule['raw']}': {e}\n"
                  f"    Compare the request above against https://{client.host}/#/api-explorer "
                  f"and fix the body fields in migrate_nat.py, then re-run.")
    print(f"Manual NAT: processed {len(translating)}, created/reused {created}.")


def migrate_auto_nat(client, net_path, iface_path, iface_map, rules, skip_existing):
    path = resolve_auto_nat_rules_path(client)
    schema = client.get_schema_properties(path)
    print(f"Auto-NAT endpoint resolved to: {path}")
    print(f"Expected top-level fields per live schema: "
          f"{sorted(schema) if schema else '(could not read schema -- body fields below are still a guess, see docstring)'}")

    print(f"Migrating {len(rules)} auto-NAT (object NAT) rule(s)...")
    created = 0
    for rule in rules:
        if not rule.get("real_value"):
            print(f"  ! object '{rule['object_name']}' has a NAT association but no "
                  f"host/subnet/range/fqdn value found anywhere in the ASA config -- this "
                  f"looks like an orphaned/incomplete object on the ASA itself (check `show "
                  f"run object network {rule['object_name']}` there), skipping: {rule['raw']}")
            continue

        real_status, real_iface_ref = iface_ref_or_none(
            client, iface_path, iface_map, rule["real_interface"], "real")
        mapped_status, mapped_iface_ref = iface_ref_or_none(
            client, iface_path, iface_map, rule["mapped_interface"], "mapped")
        if "MISSING" in (real_status, mapped_status):
            print(f"  ! no interface_map entry for '{rule['real_interface']}' and/or "
                  f"'{rule['mapped_interface']}', skipping: {rule['raw']}")
            continue

        original_ref = resolve_named_ref(client, net_path, None, rule["object_name"])
        if not original_ref:
            print(f"  ! could not resolve object '{rule['object_name']}' on FTD (has "
                  f"migrate_network_objects.py run yet?), skipping: {rule['raw']}")
            continue

        is_interface_pat = rule["mapped_target"].lower() == "interface"
        translated_ref = (None if is_interface_pat else
                           resolve_named_ref(client, net_path, None, rule["mapped_target"]))
        if not is_interface_pat and not translated_ref:
            # ASA allows a literal IP here too (not just an object name) --
            # resolve_named_ref only checks by object name, so fall back to
            # treating the target itself as the value of an ad hoc host object.
            from common.net_helpers import get_or_create_network
            translated_ref = get_or_create_network(
                client, net_path, rule["mapped_target"], "HOST", skip_existing)

        body = {
            "name": f"AUTONAT_{rule['object_name']}",
            "type": "objectnatrule",
            "natType": "STATIC" if rule["kind"] == "static" else "DYNAMIC",
            "originalNetwork": original_ref,
            "dns": rule.get("dns", False),
            "routeLookup": rule.get("route_lookup", False),
            "noProxyArp": rule.get("no_proxy_arp", False),
        }
        if real_iface_ref:
            body["sourceInterface"] = real_iface_ref
        if mapped_iface_ref:
            body["destinationInterface"] = mapped_iface_ref
        if is_interface_pat:
            body["interfaceIpv4"] = True
        else:
            body["translatedNetwork"] = translated_ref

        try:
            client.create_or_reuse(path, body, skip_existing)
            created += 1
        except FdmApiError as e:
            print(f"  ! failed to create auto-NAT rule for '{rule['raw']}': {e}\n"
                  f"    Compare the request above against https://{client.host}/#/api-explorer "
                  f"and fix the body fields in migrate_nat.py, then re-run.")
    print(f"Auto-NAT: processed {len(rules)}, created/reused {created}.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--in-dir", default="parsed")
    ap.add_argument("--only-names", default=None,
                     help="Comma-separated object/group names -- if given, only manual NAT "
                          "rules referencing at least one of these (as source or destination, "
                          "real or mapped) are migrated. Auto-NAT is unaffected. Useful for "
                          "scoping a live run to a known subset before trusting the rest.")
    ap.add_argument("--skip-auto-nat", action="store_true",
                     help="Skip auto-NAT (object NAT) entirely -- e.g. when only migrating a "
                          "--only-names subset of manual NAT.")
    args = ap.parse_args()

    cfg = load_config(args.config)
    skip_existing = cfg.get("options", {}).get("skip_existing", True)
    iface_map = cfg.get("interface_map", {})
    client = build_client(cfg)
    only_names = set(args.only_names.split(",")) if args.only_names else None

    with open(os.path.join(args.in_dir, "nat_exemptions.json")) as f:
        manual_rules = json.load(f)["rules"]
    with open(os.path.join(args.in_dir, "auto_nat.json")) as f:
        auto_rules = json.load(f)["rules"]

    net_path = client.resolve_endpoint(NETWORKS_PATH, ["network"])
    grp_path = client.resolve_endpoint(GROUPS_PATH, ["network", "group"])
    iface_path = client.resolve_endpoint(INTERFACES_PATH, ["interfaces"])

    migrate_manual_nat(client, net_path, grp_path, iface_path, iface_map, manual_rules,
                        skip_existing, only_names=only_names)
    if not args.skip_auto_nat:
        migrate_auto_nat(client, net_path, iface_path, iface_map, auto_rules, skip_existing)

    print("IMPORTANT: review NAT rule order in FDM before deploying -- this script does not "
          "control where new rules land relative to each other or any existing NAT rules, "
          "and NAT evaluation order changes what actually happens to a packet.")

    if not client.dry_run:
        deploy = input("Deploy these changes to the device now? [y/N] ").strip().lower()
        if deploy == "y":
            client.deploy()
        else:
            print("Skipped deploy -- NAT rules are staged as pending changes in FDM.")


if __name__ == "__main__":
    main()
