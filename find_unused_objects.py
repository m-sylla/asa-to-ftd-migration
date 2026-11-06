#!/usr/bin/env python3
"""
Standalone report: which `object network` / `object-group network`
definitions in an ASA config are never referenced anywhere else in that
same config. Unrelated to the FTD migration pipeline -- no migrate_*.py
script reads this file's output, and it doesn't feed parse_asa_config.py
either.

Why this reads the raw ASA config text rather than parsed/network_objects.json:
this project's parser resolves object/group references down to literal
IPs/CIDRs for the migration scripts (they don't need to know the ASA-side
object names), so that JSON has already lost the name-level reference
information needed to answer "is this object referenced anywhere". Only the
original config text still has that.

Method: for every `object network NAME` / `object-group network NAME`
definition, search the rest of the config (excluding that definition's own
header + body lines) for `NAME` as a whole word. Any match elsewhere counts
as a real reference, because every way an ASA object/group actually gets
used names it as a bare token somewhere in the line -- `network-object
object NAME` and `group-object NAME` inside another group, `object NAME` /
`object-group NAME` in an access-list, `nat (...) ... static NAME NAME
[destination static NAME2 NAME2]`, and an auto-NAT mapped target
(`nat (real,mapped) static NAME`) all qualify without needing to special-
case each command. This also correctly handles ASA re-printing an
`object network NAME` header a second time elsewhere purely to attach its
NAT association (a real quirk in ASA's own `show running-config` output,
already handled by parser/asa_parser.py's parse_network_objects) -- every
occurrence of a definition header for the same name is excluded, not just
the first.

This is a whole-word text search, not a full reference-graph walk, so it
errs toward under-reporting (marking something "used" on a coincidental
text match) rather than over-reporting (never flags something as unused
that's actually referenced) -- the safer direction for a cleanup candidate
list. Review before deleting anything; this is a starting point for manual
review, not an authoritative "safe to delete" list.

Usage:
    python find_unused_objects.py asa-config.txt --out parsed/unused_objects.json
"""
import argparse
import json
import os
import re

from parser.asa_parser import load_lines, parse_network_objects, parse_object_groups

_OBJ_NET_HEADER_RE = re.compile(r"^object network (\S+)")
_OBJ_GRP_HEADER_RE = re.compile(r"^object-group network (\S+)")


def _indent(line):
    return len(line) - len(line.lstrip(" "))


def _definition_ranges(lines, header_re):
    """{name: [(start, end_exclusive), ...]} for every top-level block
    matching header_re -- a list per name to handle ASA re-printing the
    same `object network NAME` header a second time elsewhere."""
    ranges = {}
    i = 0
    while i < len(lines):
        m = header_re.match(lines[i])
        if m and _indent(lines[i]) == 0:
            name = m.group(1)
            start = i
            j = i + 1
            while j < len(lines) and lines[j].strip() and _indent(lines[j]) > 0:
                j += 1
            ranges.setdefault(name, []).append((start, j))
            i = j
        else:
            i += 1
    return ranges


def count_external_references(lines, name, own_ranges):
    pattern = re.compile(r"\b" + re.escape(name) + r"\b")
    count = 0
    for i, line in enumerate(lines):
        if any(start <= i < end for start, end in own_ranges):
            continue
        count += len(pattern.findall(line))
    return count


def find_unused(lines):
    objects, _ = parse_network_objects(lines)
    groups, _ = parse_object_groups(lines)

    obj_ranges = _definition_ranges(lines, _OBJ_NET_HEADER_RE)
    grp_ranges = _definition_ranges(lines, _OBJ_GRP_HEADER_RE)

    unused_objects = []
    for name, obj in objects.items():
        refs = count_external_references(lines, name, obj_ranges.get(name, []))
        if refs == 0:
            unused_objects.append({
                "name": name,
                "subType": obj.get("subType"),
                "value": obj.get("value"),
                "description": obj.get("description") or None,
            })

    unused_groups = []
    for name, grp in groups.items():
        refs = count_external_references(lines, name, grp_ranges.get(name, []))
        if refs == 0:
            unused_groups.append({
                "name": name,
                "member_count": len(grp.get("members", [])),
                "literal_count": len(grp.get("literals", [])),
                "description": grp.get("description") or None,
            })

    return {
        "unused_objects": unused_objects,
        "unused_groups": unused_groups,
        "counts": {
            "total_objects": len(objects),
            "unused_objects": len(unused_objects),
            "total_groups": len(groups),
            "unused_groups": len(unused_groups),
        },
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("config_file", help="Path to ASA 'show running-config' output")
    ap.add_argument("--out", default=os.path.join("parsed", "unused_objects.json"))
    args = ap.parse_args()

    lines = load_lines(args.config_file)
    report = find_unused(lines)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(report, f, indent=2)

    c = report["counts"]
    print(f"{c['unused_objects']}/{c['total_objects']} network objects appear unused, "
          f"{c['unused_groups']}/{c['total_groups']} object-groups appear unused.")
    print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()
