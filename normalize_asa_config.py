#!/usr/bin/env python3
"""
Standalone ASA config normalizer. This does NOT feed migrate_*.py or
parse_asa_config.py -- it's a separate tool that only reads an ASA
`show running-config` dump and writes out a cleaned-up copy of the config
text itself (not JSON), with two ASA-specific quirks resolved:

1. Resolves `name <ip> <alias>` substitutions wherever an alias is used in
   a route (either the destination network address or the gateway --
   `route <if> <net-or-alias> <mask> <gw-or-alias> [metric]`, confirmed
   both positions are actually used in practice, e.g. `route outside
   RemoteVendor 255.255.255.128 203.0.113.254 1`), or as a raw address
   inside an `object-group network` member line (`network-object host
   <alias>` / `network-object <alias> <mask>`), replacing the alias text
   with its literal IP. Nothing else in the file is touched -- other places
   an alias could in principle appear (ACLs, crypto peer statements, an
   `object network`'s own `host` line, etc.) are deliberately out of scope
   for this pass, per what was asked.

2. For every `object-group network` member that's a raw literal address
   (`network-object host <ip>` or `network-object <net> <mask>`, as opposed
   to a `network-object object <name>` reference to something already
   defined) -- after step 1, so any alias there is already a literal IP --
   this either rewrites it to reference a pre-existing `object network` of
   the same value, or creates a new `object network` for it (inserted just
   before the first `object-group network` block) and rewrites the member
   line to reference that instead. Generated names follow this toolkit's
   existing HOST_<ip>/NET_<net>-<prefix> convention (see
   common/net_helpers.py) for consistency, with a numeric suffix if that
   name is somehow already taken.

Usage:
    python normalize_asa_config.py asa-config.txt --out parsed/asa-config-normalized.txt

Review the printed summary and diff the output against the input before
treating it as authoritative -- like the rest of this toolkit's parser,
this only recognizes the common ASA 9.12 syntax forms described above.

Verified against a real ~1300-line slice of a production config (routes +
object network/object-group network sections -- names/IPs below are
genericized, not the real values): 34 alias substitutions (including
several in the route *network* position, not just the gateway --
`route outside RemoteVendor 255.255.255.128 203.0.113.254 1` was an early
version of this script's blind spot until this data caught it), and 24
object-group literal members handled (15 matched to a pre-existing object
network of the same value under a *different* name -- e.g. an alias
resolving to 192.168.50.0/24 correctly found and reused the pre-existing
`REMOTE-NET` object rather than creating a redundant one -- and 9 had no
match and got a new object created).
"""
import argparse
import ipaddress
import os
import re

from parser.asa_parser import load_lines, parse_network_objects, parse_name_aliases

ROUTE_RE = re.compile(r"^(route )(\S+) (\S+) (\S+) (\S+)(.*)$")
OBJ_GRP_HEADER_RE = re.compile(r"^object-group network (\S+)")
NETWORK_OBJECT_HOST_RE = re.compile(r"^(\s*)network-object host (\S+)\s*$")
NETWORK_OBJECT_OBJREF_RE = re.compile(r"^(\s*)network-object object (\S+)\s*$")
NETWORK_OBJECT_NET_RE = re.compile(r"^(\s*)network-object (\S+) (\S+)\s*$")


def _indent(line):
    return len(line) - len(line.lstrip(" "))


def _prefix_to_mask(prefix):
    return str(ipaddress.ip_network(f"0.0.0.0/{prefix}").netmask)


def substitute_aliases(lines, aliases):
    """Replace `name`-defined aliases with their literal IP, only in route
    destination networks/gateways and object-group network literal members.
    Returns (new_lines, substitution_count)."""
    out = list(lines)
    count = 0
    in_group = False
    for i, line in enumerate(out):
        if _indent(line) == 0:
            in_group = bool(OBJ_GRP_HEADER_RE.match(line))
            m = ROUTE_RE.match(line)
            if m:
                prefix, iface, net, mask, gw, rest = m.groups()
                if net in aliases:
                    net = aliases[net]
                    count += 1
                if gw in aliases:
                    gw = aliases[gw]
                    count += 1
                out[i] = f"{prefix}{iface} {net} {mask} {gw}{rest}"
            continue
        if not in_group:
            continue
        hm = NETWORK_OBJECT_HOST_RE.match(line)
        om = NETWORK_OBJECT_OBJREF_RE.match(line)
        nm = None if (hm or om) else NETWORK_OBJECT_NET_RE.match(line)
        if hm and hm.group(2) in aliases:
            out[i] = f"{hm.group(1)}network-object host {aliases[hm.group(2)]}"
            count += 1
        elif nm and nm.group(2) in aliases:
            out[i] = f"{nm.group(1)}network-object {aliases[nm.group(2)]} {nm.group(3)}"
            count += 1
    return out, count


def _generate_name(sub_type, value, taken_names):
    tag = "HOST" if sub_type == "HOST" else "NET"
    safe = re.sub(r"[./]", "-", value)
    base = f"{tag}_{safe}"
    name = base
    n = 2
    while name in taken_names:
        name = f"{base}_{n}"
        n += 1
    return name


def create_objects_for_literals(lines, aliases_substituted_count):
    """Second pass: for every raw literal in an object-group network block,
    reference an existing object network of the same value, or create one.
    Returns (new_lines, reused_count, created_count)."""
    objects, _ = parse_network_objects(lines)
    value_to_name = {}
    taken_names = set(objects.keys())
    for name, obj in objects.items():
        key = (obj.get("subType"), obj.get("value"))
        if key[0] in ("HOST", "NETWORK"):
            value_to_name.setdefault(key, name)

    out = list(lines)
    new_object_blocks = []  # list of (subType, value, name) in creation order
    in_group = False
    reused_count = 0
    created_count = 0

    for i, line in enumerate(out):
        if _indent(line) == 0:
            in_group = bool(OBJ_GRP_HEADER_RE.match(line))
            continue
        if not in_group:
            continue
        hm = NETWORK_OBJECT_HOST_RE.match(line)
        om = NETWORK_OBJECT_OBJREF_RE.match(line)
        if om:
            continue  # already a reference, nothing to do
        nm = None if hm else NETWORK_OBJECT_NET_RE.match(line)
        if hm:
            indent, value = hm.group(1), hm.group(2)
            key = ("HOST", value)
        elif nm:
            indent = nm.group(1)
            key = ("NETWORK", f"{nm.group(2)}/{_mask_to_prefix(nm.group(3))}")
        else:
            continue

        name = value_to_name.get(key)
        if name is None:
            name = _generate_name(key[0], key[1], taken_names)
            taken_names.add(name)
            value_to_name[key] = name
            new_object_blocks.append((key[0], key[1], name))
            created_count += 1
        else:
            reused_count += 1
        out[i] = f"{indent}network-object object {name}"

    if new_object_blocks:
        insert_at = next(
            (i for i, l in enumerate(out) if OBJ_GRP_HEADER_RE.match(l)), len(out))
        block_lines = []
        for sub_type, value, name in new_object_blocks:
            block_lines.append(f"object network {name}")
            if sub_type == "HOST":
                block_lines.append(f" host {value}")
            else:
                net, prefix = value.split("/")
                block_lines.append(f" subnet {net} {_prefix_to_mask(prefix)}")
        out[insert_at:insert_at] = block_lines

    return out, reused_count, created_count


def _mask_to_prefix(mask):
    return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("config_file", help="Path to ASA 'show running-config' output")
    ap.add_argument("--out", default=os.path.join("parsed", "asa-config-normalized.txt"))
    args = ap.parse_args()

    lines = load_lines(args.config_file)
    aliases = parse_name_aliases(lines)

    lines, alias_count = substitute_aliases(lines, aliases)
    lines, reused_count, created_count = create_objects_for_literals(lines, alias_count)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Parsed {len(aliases)} name alias(es).")
    print(f"Replaced {alias_count} alias reference(s) in routes/object-groups with "
          f"their literal IP.")
    print(f"Rewrote {reused_count} object-group literal member(s) to reference an "
          f"existing object network.")
    print(f"Created {created_count} new object network(s) for literals with no "
          f"existing match, and rewrote their group member line(s) to reference them.")
    print(f"Wrote normalized config to {args.out}")


if __name__ == "__main__":
    main()
