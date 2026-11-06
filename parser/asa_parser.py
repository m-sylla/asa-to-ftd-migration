"""
Regex-based parser for a Cisco ASA 9.12 `show running-config` text dump.

Covers the common, non-deprecated syntax for network objects/groups, static
`route` statements, policy-based (crypto-map) site-to-site VPN, manual/twice
NAT (both identity/no-NAT rules and general translations), auto-NAT (object
NAT), DNS (`dns domain-lookup`, `dns server-group`), SNMP (`snmp-server
host`/`community`/`location`/`contact`), NTP (`ntp server`), `name` aliases,
logging (`logging from-address`/`logging ftp-server` only), ICMP control-
plane rules (`icmp permit`/`icmp deny`), and HTTPS management access
(`http server enable`/`http <net> <mask> <interface>`). It is not a full ASA
config grammar -- anything it can't confidently parse is collected into
`unparsed` in each result so you can review it by hand. In particular it
does NOT handle: IPv6 routes/objects, VTI/route-based VPN, certificate-based
(RSA-sig) IKE auth, dynamic crypto maps, object-groups nested more than the
levels resolved by resolve_group_networks()'s recursion (which is unlimited,
but circular group references are not guarded against), PAT pools (a
dynamic NAT mapped to an object-group of addresses rather than a single
object/"interface"), per-service/port NAT translations (only address
translation is parsed, not the port-forwarding "service tcp/udp ..."
qualifiers some NAT lines carry), SNMPv3 (user-based) hosts (a `snmp-server
host` line with no `community` keyword is left unparsed), the rest of
`logging` (enable/timestamp/buffer-size/message severity overrides/etc, only
from-address and ftp-server are parsed), the global ACL
(`access-list ... global` / `access-group ... global`), or ICMP's
`icmp unreachable rate-limit` (a separate global setting, not part of the
permit/deny list).
"""
import ipaddress
import re
from collections import OrderedDict


def load_lines(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return [l.rstrip("\n") for l in f]


def _indent(line):
    return len(line) - len(line.lstrip(" "))


def _blocks(lines, header_re):
    """
    Yield (match, body_lines) for each top-level command matching header_re,
    where body_lines are the indented sub-command lines that follow it.
    """
    i = 0
    while i < len(lines):
        line = lines[i]
        m = header_re.match(line)
        if m and _indent(line) == 0:
            body = []
            j = i + 1
            while j < len(lines) and lines[j].strip() and _indent(lines[j]) > 0:
                body.append(lines[j].strip())
                j += 1
            yield m, body
            i = j
        else:
            i += 1


# --------------------------------------------------------------- network objects
_OBJ_NET_RE = re.compile(r"^object network (\S+)")
_OBJ_GRP_RE = re.compile(r"^object-group network (\S+)")


def parse_network_objects(lines):
    objects = OrderedDict()
    unparsed = []
    for m, body in _blocks(lines, _OBJ_NET_RE):
        name = m.group(1)
        entry = {"description": ""}
        matched = False
        only_nat_or_description = True
        for sub in body:
            hm = re.match(r"^host (\S+)$", sub)
            sm = re.match(r"^subnet (\S+) (\S+)$", sub)
            rm = re.match(r"^range (\S+) (\S+)$", sub)
            fm = re.match(r"^fqdn(?: (v4|v6))? (\S+)$", sub)
            dm = re.match(r"^description (.*)$", sub)
            natm = sub.startswith("nat (")
            if hm:
                entry.update(subType="HOST", value=hm.group(1))
                matched = True
                only_nat_or_description = False
            elif sm:
                entry.update(subType="NETWORK", value=f"{sm.group(1)}/{_mask_to_prefix(sm.group(2))}")
                matched = True
                only_nat_or_description = False
            elif rm:
                entry.update(subType="RANGE", value=f"{rm.group(1)}-{rm.group(2)}")
                matched = True
                only_nat_or_description = False
            elif fm:
                entry.update(subType="FQDN", value=fm.group(2))
                matched = True
                only_nat_or_description = False
            elif dm:
                entry["description"] = dm.group(1)
            elif natm:
                pass  # handled separately by parse_auto_nat_rules()
            else:
                unparsed.append(f"object network {name}: {sub}")
                only_nat_or_description = False
        if matched:
            objects[name] = entry
        elif not only_nat_or_description:
            # ASA re-prints "object network X" a second time, body-less except
            # for its nat association, wherever that object already has a
            # real definition earlier in the config -- not actually an empty
            # object, so don't warn about it as one.
            unparsed.append(f"object network {name}: <no host/subnet/range/fqdn found>")
    return objects, unparsed


def parse_object_groups(lines):
    groups = OrderedDict()
    unparsed = []
    for m, body in _blocks(lines, _OBJ_GRP_RE):
        name = m.group(1)
        members = []       # names of other objects/groups
        literals = []       # {"subType": "...", "value": "..."} inline entries
        description = ""
        for sub in body:
            om = re.match(r"^network-object object (\S+)$", sub)
            hm = re.match(r"^network-object host (\S+)$", sub)
            nm = re.match(r"^network-object (\S+) (\S+)$", sub)
            gm = re.match(r"^group-object (\S+)$", sub)
            dm = re.match(r"^description (.*)$", sub)
            if om:
                members.append(om.group(1))
            elif hm:
                literals.append({"subType": "HOST", "value": hm.group(1)})
            elif nm:
                literals.append({"subType": "NETWORK", "value": f"{nm.group(1)}/{_mask_to_prefix(nm.group(2))}"})
            elif gm:
                members.append(gm.group(1))
            elif dm:
                description = dm.group(1)
            else:
                unparsed.append(f"object-group network {name}: {sub}")
        groups[name] = {"members": members, "literals": literals, "description": description}
    return groups, unparsed


def _mask_to_prefix(mask):
    if re.match(r"^\d+$", mask):
        return mask  # already a prefix length
    octets = [int(o) for o in mask.split(".")]
    bits = "".join(f"{o:08b}" for o in octets)
    return str(bits.count("1"))


# --------------------------------------------------------------------- routes
_ROUTE_RE = re.compile(
    r"^route (\S+) (\S+) (\S+) (\S+)(?: (\d+))?"
)


def parse_routes(lines):
    routes = []
    unparsed = []
    for line in lines:
        if not line.startswith("route "):
            continue
        m = _ROUTE_RE.match(line.strip())
        if not m:
            unparsed.append(line)
            continue
        iface, net, mask, gw, metric = m.groups()
        if gw.lower() == "tunneled":
            # `route <if> 0.0.0.0 0.0.0.0 tunneled` -- ASA's special default
            # route for VPN traffic with no real next-hop IP. Has no direct
            # FTD static-route equivalent; VPN traffic routing on FTD is
            # handled by the S2S connection's own network selectors instead.
            unparsed.append(f"{line.strip()}  (ASA 'tunneled' route, no FTD static-route "
                             f"equivalent -- not migrated)")
            continue
        routes.append({
            "interface": iface,
            "network": net,
            "mask": mask,
            "prefix": _mask_to_prefix(mask),
            "gateway": gw,
            "metric": int(metric) if metric else 1,
        })
    return routes, unparsed


# ---------------------------------------------------------------- s2s VPN
_ACL_RE = re.compile(r"^access-list (\S+) extended permit (ip|tcp|udp) (.+)$")
_CRYPTO_MAP_MATCH_RE = re.compile(r"^crypto map (\S+) (\d+) match address (\S+)")
_CRYPTO_MAP_PEER_RE = re.compile(r"^crypto map (\S+) (\d+) set peer (.+)")
_CRYPTO_MAP_IKEV1_TS_RE = re.compile(r"^crypto map (\S+) (\d+) set ikev1 transform-set (\S+)")
_CRYPTO_MAP_IKEV2_PROP_RE = re.compile(r"^crypto map (\S+) (\d+) set ikev2 ipsec-proposal (\S+)")
_CRYPTO_MAP_PFS_RE = re.compile(r"^crypto map (\S+) (\d+) set pfs(?: (\S+))?")
_CRYPTO_MAP_LIFETIME_RE = re.compile(r"^crypto map (\S+) (\d+) set security-association lifetime seconds (\d+)")
_CRYPTO_MAP_IFACE_RE = re.compile(r"^crypto map (\S+) interface (\S+)")

_IKEV1_POLICY_RE = re.compile(r"^crypto ikev1 policy (\d+)")
_IKEV2_POLICY_RE = re.compile(r"^crypto ikev2 policy (\d+)")
_IKEV1_TS_DEF_RE = re.compile(r"^crypto ipsec ikev1 transform-set (\S+) (.+)$")
_IKEV2_PROP_DEF_RE = re.compile(r"^crypto ipsec ikev2 ipsec-proposal (\S+)")

_TUNNEL_GROUP_TYPE_RE = re.compile(r"^tunnel-group (\S+) type ipsec-l2l")
_TUNNEL_GROUP_IPSEC_ATTR_RE = re.compile(r"^tunnel-group (\S+) ipsec-attributes")


def _addr_spec_to_networks(tok, objects, groups):
    """Turn one side of an ACL entry ('host X' / 'X Y' / 'object N' / 'object-group G' / 'any')
    into a list of CIDR strings, using already-parsed objects/groups. Returns (cidrs, consumed_len)."""
    parts = tok.split()
    if parts[0] == "any" or parts[0] in ("any4", "any6"):
        return ["0.0.0.0/0"], 1
    if parts[0] == "host":
        return [f"{parts[1]}/32"], 2
    if parts[0] == "object":
        name = parts[1]
        obj = objects.get(name)
        if obj:
            return [_object_to_cidr(obj)], 2
        return [f"OBJECT:{name}"], 2  # unresolved, kept as marker
    if parts[0] == "object-group":
        name = parts[1]
        return resolve_group_networks(name, objects, groups), 2
    # bare "IP MASK"
    if len(parts) >= 2 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
        return [f"{parts[0]}/{_mask_to_prefix(parts[1])}"], 2
    return [f"UNRESOLVED:{tok}"], len(parts)


def _object_to_cidr(obj):
    if obj["subType"] == "HOST":
        return f"{obj['value']}/32"
    if obj["subType"] == "NETWORK":
        return obj["value"]
    if obj["subType"] == "RANGE":
        return obj["value"]  # ranges don't map to CIDR; kept as-is, flagged downstream
    return obj["value"]


def resolve_group_networks(name, objects, groups, _seen=None):
    _seen = _seen or set()
    if name in _seen:
        return []
    _seen.add(name)
    grp = groups.get(name)
    if not grp:
        return [f"UNRESOLVED_GROUP:{name}"]
    cidrs = [f"{lit['value']}" if lit["subType"] != "HOST" else f"{lit['value']}/32"
             for lit in grp["literals"]]
    for member in grp["members"]:
        if member in objects:
            cidrs.append(_object_to_cidr(objects[member]))
        elif member in groups:
            cidrs.extend(resolve_group_networks(member, objects, groups, _seen))
        else:
            cidrs.append(f"UNRESOLVED:{member}")
    return cidrs


def parse_s2s_vpn(lines, objects, groups):
    acls = {}  # name -> list of (src_cidrs, dst_cidrs)
    ikev1_policies = {}
    ikev2_policies = {}
    ikev1_transform_sets = {}
    ikev2_proposals = {}
    crypto_maps = {}  # map_name -> {seq: {...}}
    map_interface = {}
    tunnel_groups = {}  # peer_ip -> {psk, ikev1, ikev2}
    unparsed = []

    for m, body in _blocks(lines, _IKEV1_POLICY_RE):
        prio = m.group(1)
        pol = {}
        for sub in body:
            am = re.match(r"^authentication (\S+)", sub)
            em = re.match(r"^encryption (\S+)", sub)
            hm = re.match(r"^hash (\S+)", sub)
            gm = re.match(r"^group (\S+)", sub)
            lm = re.match(r"^lifetime (\d+)", sub)
            if am: pol["authentication"] = am.group(1)
            elif em: pol["encryption"] = em.group(1)
            elif hm: pol["hash"] = hm.group(1)
            elif gm: pol["dh_group"] = gm.group(1)
            elif lm: pol["lifetime_seconds"] = int(lm.group(1))
            else: unparsed.append(f"crypto ikev1 policy {prio}: {sub}")
        ikev1_policies[prio] = pol

    for m, body in _blocks(lines, _IKEV2_POLICY_RE):
        prio = m.group(1)
        pol = {}
        for sub in body:
            em = re.match(r"^encryption (\S+)", sub)
            im = re.match(r"^integrity (\S+)", sub)
            gm = re.match(r"^group (\S+)", sub)
            pm = re.match(r"^prf (\S+)", sub)
            lm = re.match(r"^lifetime seconds (\d+)", sub)
            if em: pol["encryption"] = em.group(1)
            elif im: pol["integrity"] = im.group(1)
            elif gm: pol["dh_group"] = gm.group(1)
            elif pm: pol["prf"] = pm.group(1)
            elif lm: pol["lifetime_seconds"] = int(lm.group(1))
            else: unparsed.append(f"crypto ikev2 policy {prio}: {sub}")
        ikev2_policies[prio] = pol

    for m, body in _blocks(lines, _IKEV2_PROP_DEF_RE):
        name = m.group(1)
        prop = {"encryption": [], "integrity": []}
        for sub in body:
            em = re.match(r"^protocol esp encryption (.+)$", sub)
            im = re.match(r"^protocol esp integrity (.+)$", sub)
            if em: prop["encryption"] = em.group(1).split()
            elif im: prop["integrity"] = im.group(1).split()
            else: unparsed.append(f"crypto ipsec ikev2 ipsec-proposal {name}: {sub}")
        ikev2_proposals[name] = prop

    for line in lines:
        m = _IKEV1_TS_DEF_RE.match(line.strip())
        if m:
            ikev1_transform_sets[m.group(1)] = m.group(2).split()
            continue
        m = _ACL_RE.match(line.strip())
        if m:
            acl_name, proto, rest = m.groups()
            # rest is "SRC... DST..." with each side being one of the addr-spec forms.
            src_cidrs, consumed = _addr_spec_to_networks(rest, objects, groups)
            remaining = " ".join(rest.split()[consumed:])
            dst_cidrs, _ = _addr_spec_to_networks(remaining, objects, groups)
            acls.setdefault(acl_name, []).append((src_cidrs, dst_cidrs))
            continue
        m = _CRYPTO_MAP_IFACE_RE.match(line.strip())
        if m:
            map_interface[m.group(1)] = m.group(2)
            continue
        for regex, key in (
            (_CRYPTO_MAP_MATCH_RE, "acl"),
            (_CRYPTO_MAP_PEER_RE, "peer"),
            (_CRYPTO_MAP_IKEV1_TS_RE, "ikev1_ts"),
            (_CRYPTO_MAP_IKEV2_PROP_RE, "ikev2_prop"),
            (_CRYPTO_MAP_PFS_RE, "pfs"),
            (_CRYPTO_MAP_LIFETIME_RE, "lifetime"),
        ):
            m = regex.match(line.strip())
            if m:
                map_name, seq = m.group(1), m.group(2)
                entry = crypto_maps.setdefault(map_name, {}).setdefault(seq, {})
                val = m.group(3) if m.lastindex >= 3 else None
                entry[key] = val
                break

    for m, body in _blocks(lines, _TUNNEL_GROUP_IPSEC_ATTR_RE):
        peer = m.group(1)
        tg = tunnel_groups.setdefault(peer, {})
        for sub in body:
            k1 = re.match(r"^ikev1 pre-shared-key (\S+)", sub)
            k2r = re.match(r"^ikev2 remote-authentication pre-shared-key (\S+)", sub)
            k2l = re.match(r"^ikev2 local-authentication pre-shared-key (\S+)", sub)
            if k1: tg["ikev1_psk"] = k1.group(1)
            elif k2r: tg["ikev2_remote_psk"] = k2r.group(1)
            elif k2l: tg["ikev2_local_psk"] = k2l.group(1)
            else: unparsed.append(f"tunnel-group {peer} ipsec-attributes: {sub}")

    # Assemble one entry per crypto-map sequence (= one site-to-site tunnel).
    tunnels = []
    for map_name, seqs in crypto_maps.items():
        iface = map_interface.get(map_name, "UNKNOWN")
        for seq, entry in seqs.items():
            peer = entry.get("peer")
            acl_name = entry.get("acl")
            local_nets, remote_nets = [], []
            if acl_name and acl_name in acls:
                for src, dst in acls[acl_name]:
                    local_nets.extend(src)
                    remote_nets.extend(dst)
            # ASA can have both an ikev1 transform-set and an ikev2 ipsec-proposal
            # set on the same crypto-map entry (either may be negotiated), so both
            # are recorded rather than picking one.
            tg = tunnel_groups.get(peer, {})
            tunnels.append({
                "crypto_map": map_name,
                "seq": seq,
                "interface": iface,
                "peer": peer,
                "acl_name": acl_name,
                "local_networks": dedupe_supersets(local_nets),
                "remote_networks": dedupe_supersets(remote_nets),
                "ikev1_transform_set": ikev1_transform_sets.get(entry.get("ikev1_ts", "")),
                "ikev2_proposal": ikev2_proposals.get(entry.get("ikev2_prop", "")),
                "pfs_group": entry.get("pfs"),
                "lifetime_seconds": int(entry["lifetime"]) if entry.get("lifetime") else None,
                "ikev1_psk": tg.get("ikev1_psk"),
                "ikev2_local_psk": tg.get("ikev2_local_psk"),
                "ikev2_remote_psk": tg.get("ikev2_remote_psk"),
            })

    return {
        "tunnels": tunnels,
        "ikev1_policies": ikev1_policies,
        "ikev2_policies": ikev2_policies,
    }, unparsed


# ------------------------------------------------------- NAT exemption (no-NAT)
# Only the manual/twice-NAT form is parsed -- this is the standard ASA idiom
# for exempting VPN traffic from translation:
#   nat (inside,outside) source static LOCAL-NET LOCAL-NET destination static
#       REMOTE-NET REMOTE-NET no-proxy-arp route-lookup
# "static X X" (same object on both sides) means identity/no-NAT. Auto-NAT
# statements nested under `object network` blocks are not parsed -- those are
# typically used for actual translation (PAT/static NAT), not VPN exemption.
_MANUAL_NAT_RE = re.compile(
    r"^nat \(([^,]+),([^)]+)\) source (static|dynamic) (\S+) (\S+)"
    r"(?: destination (static|dynamic) (\S+) (\S+))?(.*)$"
)


def _name_to_cidrs(name, objects, groups):
    if not name or name == "any":
        return ["0.0.0.0/0"]
    if name in objects:
        return [_object_to_cidr(objects[name])]
    if name in groups:
        return resolve_group_networks(name, objects, groups)
    return [f"UNRESOLVED:{name}"]


_AUTO_NAT_RE = re.compile(r"^nat \(([^,]+),([^)]+)\) (dynamic|static) (\S+)(.*)$")


def parse_nat_rules(lines, objects, groups):
    rules = []
    unparsed = []
    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("nat ("):
            continue
        m = _MANUAL_NAT_RE.match(stripped)
        if not m:
            if _AUTO_NAT_RE.match(stripped):
                continue  # nested auto-NAT line, handled by parse_auto_nat_rules() instead
            unparsed.append(stripped)
            continue
        (real_if, mapped_if, src_kind, src_real, src_mapped,
         dst_kind, dst_real, dst_mapped, trailing) = m.groups()
        is_identity = (src_kind == "static" and src_real == src_mapped and
                       (dst_kind is None or (dst_kind == "static" and dst_real == dst_mapped)))
        rules.append({
            "raw": stripped,
            "real_interface": real_if,
            "mapped_interface": mapped_if,
            "source_kind": src_kind,
            "source_real": src_real,
            "source_mapped": src_mapped,
            "destination_kind": dst_kind,
            "destination_real": dst_real,
            "destination_mapped": dst_mapped,
            "no_proxy_arp": "no-proxy-arp" in trailing,
            "route_lookup": "route-lookup" in trailing,
            "unidirectional": "unidirectional" in trailing,
            "is_identity": is_identity,
            "source_networks": _name_to_cidrs(src_real, objects, groups),
            "destination_networks": (_name_to_cidrs(dst_real, objects, groups)
                                      if dst_real else None),
        })
    return rules, unparsed


def parse_auto_nat_rules(lines, objects):
    """Auto-NAT (object NAT): a `nat (real,mapped) static|dynamic <target>`
    line nested under `object network NAME`, where NAME's own real value
    (already known from parse_network_objects) is the untranslated side --
    unlike manual/twice NAT, the real address isn't restated on the nat line
    itself. <target> is a network object name, a literal IP/host (static), or
    the literal word "interface" (dynamic PAT using the egress interface's
    own address, ASA's most common form of general internet-bound PAT)."""
    rules = []
    for m, body in _blocks(lines, _OBJ_NET_RE):
        name = m.group(1)
        for sub in body:
            am = _AUTO_NAT_RE.match(sub)
            if not am:
                continue
            real_if, mapped_if, kind, target, trailing = am.groups()
            real_obj = objects.get(name)
            rules.append({
                "raw": sub,
                "object_name": name,
                "real_value": real_obj["value"] if real_obj else None,
                "real_sub_type": real_obj["subType"] if real_obj else None,
                "real_interface": real_if,
                "mapped_interface": mapped_if,
                "kind": kind,  # static or dynamic
                "mapped_target": target,  # object name / literal IP / "interface"
                "dns": "dns" in trailing,
                "route_lookup": "route-lookup" in trailing,
                "no_proxy_arp": "no-proxy-arp" in trailing,
            })
    return rules


def _network_contains(supernet_str, subnet_str):
    try:
        supernet = ipaddress.ip_network(supernet_str, strict=False)
        subnet = ipaddress.ip_network(subnet_str, strict=False)
        return subnet.subnet_of(supernet) or subnet == supernet
    except ValueError:
        return False


def dedupe_supersets(cidrs):
    """Drop any entry already covered by a broader entry in the same list
    (e.g. a specific host also listed via the subnet that contains it).
    Confirmed live: FDM rejects a S2S connection profile whose
    local/remoteNetworks contain overlapping selectors like this
    ("s2sOverlapChosenNetworks") -- a real, if redundant, pattern in ACLs
    built up by hand over time. Ranges and unresolved markers pass through
    untouched (not CIDRs, no containment check attempted)."""
    plain = [c for c in cidrs if not c.startswith("UNRESOLVED") and not c.startswith("OBJECT:")
             and "-" not in c]  # exclude range-format entries (IPs/CIDRs never contain '-')
    other = [c for c in cidrs if c not in plain]
    keep = []
    for c in plain:
        if any(o != c and _network_contains(o, c) for o in plain):
            continue
        keep.append(c)
    return sorted(set(keep)) + sorted(set(other))


def check_nat_exemption(tunnels, nat_rules):
    """Annotate each tunnel with whether every (local-network, remote-network)
    pair it protects is covered by some identity NAT rule -- i.e. that ASA
    already guaranteed this VPN traffic isn't translated. Mutates and returns
    `tunnels`."""
    identity_rules = [r for r in nat_rules if r["is_identity"]]
    for t in tunnels:
        local_cidrs = [c for c in t["local_networks"]
                       if not c.startswith("UNRESOLVED") and not c.startswith("OBJECT:")]
        remote_cidrs = [c for c in t["remote_networks"]
                        if not c.startswith("UNRESOLVED") and not c.startswith("OBJECT:")]
        uncovered_pairs = []
        matched_rules = {}   # raw -> rule dict, dedup by raw text
        for lc in local_cidrs:
            for rc in remote_cidrs:
                covered_by = None
                for r in identity_rules:
                    if not any(_network_contains(rn, lc) for rn in r["source_networks"]):
                        continue
                    if r["destination_networks"] is None:
                        dst_ok = True
                    else:
                        dst_ok = any(_network_contains(rn, rc) for rn in r["destination_networks"])
                    if dst_ok:
                        covered_by = r
                        break
                if covered_by:
                    matched_rules[covered_by["raw"]] = covered_by
                else:
                    uncovered_pairs.append([lc, rc])
        t["nat_exempt"] = bool(local_cidrs) and bool(remote_cidrs) and not uncovered_pairs
        t["matched_nat_exemption_rules"] = sorted(matched_rules.keys())
        t["nat_exempt_uncovered_pairs"] = uncovered_pairs
        # FTD's stosconnectionprofile.interfaceForNatExempt is a single interface
        # (the internal/real-side one -- ASA's "real_interface" in the matched nat
        # statement); if more than one distinct real_interface matched, that's an
        # unusual ASA setup this can't collapse into FTD's single-interface field.
        real_ifaces = sorted({r["real_interface"] for r in matched_rules.values()})
        if t["nat_exempt"] and len(real_ifaces) == 1:
            t["nat_exempt_interface"] = real_ifaces[0]
        else:
            t["nat_exempt_interface"] = None
            if len(real_ifaces) > 1:
                t["nat_exempt"] = False
                t["nat_exempt_uncovered_pairs"].append(
                    [f"multiple real interfaces matched: {real_ifaces}", "manual review needed"])
    return tunnels


# --------------------------------------------------------------- DNS
_DNS_LOOKUP_RE = re.compile(r"^dns domain-lookup (\S+)")
_DNS_SERVER_GROUP_RE = re.compile(r"^dns server-group (\S+)")
_DNS_NAME_SERVER_RE = re.compile(r"^name-server (\S+)")
_DNS_DOMAIN_NAME_RE = re.compile(r"^domain-name (\S+)")


def parse_dns(lines):
    """Parse `dns domain-lookup <if>` enable lines and `dns server-group NAME`
    blocks (nested `name-server`/`domain-name` lines). Unlike VPN PSKs or SNMP
    communities, nothing here is a secret, so it all goes straight into
    parsed/dns.json -- no separate secrets file needed."""
    domain_lookup_interfaces = []
    for line in lines:
        if _indent(line) == 0:
            m = _DNS_LOOKUP_RE.match(line)
            if m:
                domain_lookup_interfaces.append(m.group(1))

    unparsed = []
    server_groups = OrderedDict()
    for m, body in _blocks(lines, _DNS_SERVER_GROUP_RE):
        name = m.group(1)
        name_servers = []
        domain_name = None
        for sub in body:
            nm = _DNS_NAME_SERVER_RE.match(sub)
            if nm:
                name_servers.append(nm.group(1))
                continue
            dm = _DNS_DOMAIN_NAME_RE.match(sub)
            if dm:
                domain_name = dm.group(1)
                continue
            unparsed.append(f"dns server-group {name}: {sub}")
        server_groups[name] = {"name_servers": name_servers, "domain_name": domain_name}

    return {"domain_lookup_interfaces": domain_lookup_interfaces,
            "server_groups": server_groups}, unparsed


# --------------------------------------------------------------- SNMP
_SNMP_HOST_RE = re.compile(r"^snmp-server host (\S+) (\S+)(.*)$")
_SNMP_COMMUNITY_RE = re.compile(r"^snmp-server community (\S+)")
_SNMP_LOCATION_RE = re.compile(r"^snmp-server location (.+)$")
_SNMP_CONTACT_RE = re.compile(r"^snmp-server contact (.+)$")


def parse_snmp(lines):
    """Parse `snmp-server host`/`community`/`location`/`contact` lines.

    Community strings are pulled out into a separate `communities` dict keyed
    by `community_key` (the host's IP, or "_global" for a bare `snmp-server
    community` statement) instead of being embedded in the returned snmp
    dict -- parse_asa_config.py writes that dict to a separate, gitignored
    snmp_secrets.yaml, the same treatment VPN pre-shared keys get (see
    common/secrets_store.py) -- so `parsed/snmp.json` never holds a live
    community string.

    `no snmp-server location` / `no snmp-server contact` (an explicit
    "unset", commonly present verbatim in ASA running-config output even
    when never configured) are treated as not-configured, not an error --
    as is any other `no snmp-server ...` negation line.

    A `snmp-server host` line with no `community` keyword is assumed to be
    SNMPv3 (user-based auth, not modeled here) and recorded as unparsed.
    ASA's default when `poll`/`trap` is omitted is `trap`-only, and default
    version when omitted is `1` -- both applied here for consistency with
    ASA behavior, not because either is confirmed to be what you want on
    FTD; review parsed/snmp.json.
    """
    hosts = []
    communities = {}
    location = None
    contact = None
    global_community_key = None
    unparsed = []

    for line in lines:
        if _indent(line) != 0:
            continue
        if line.startswith("no snmp-server"):
            continue  # explicit "unset" -- nothing to migrate

        m = _SNMP_HOST_RE.match(line)
        if m:
            interface, ip, rest = m.group(1), m.group(2), m.group(3)
            tokens = rest.split()
            traffic = []
            version = None
            community = None
            i = 0
            while i < len(tokens):
                tok = tokens[i].lower()
                if tok in ("poll", "trap"):
                    traffic.append(tok)
                elif tok == "community" and i + 1 < len(tokens):
                    community = tokens[i + 1]
                    i += 1
                elif tok == "version" and i + 1 < len(tokens):
                    version = tokens[i + 1]
                    i += 1
                    if version == "3" and i + 1 < len(tokens):
                        i += 1  # skip the v3 username token -- not modeled
                elif tok == "udp-port" and i + 1 < len(tokens):
                    i += 1  # not modeled -- FTD default port assumed
                i += 1
            if not community:
                unparsed.append(f"{line} (no community found -- likely an "
                                 f"SNMPv3 user-based host, not supported by this parser)")
                continue
            key = ip
            communities[key] = community
            hosts.append({
                "interface": interface,
                "ip": ip,
                "traffic": traffic or ["trap"],
                "version": version or "1",
                "community_key": key,
            })
            continue

        m = _SNMP_COMMUNITY_RE.match(line)
        if m:
            global_community_key = "_global"
            communities[global_community_key] = m.group(1)
            continue

        m = _SNMP_LOCATION_RE.match(line)
        if m:
            location = m.group(1).strip()
            continue

        m = _SNMP_CONTACT_RE.match(line)
        if m:
            contact = m.group(1).strip()
            continue

    snmp = {
        "hosts": hosts,
        "global_community_key": global_community_key,
        "location": location,
        "contact": contact,
    }
    return snmp, communities, unparsed


# --------------------------------------------------------------- NTP
_NTP_SERVER_RE = re.compile(r"^ntp server (\S+)(.*)$")


def parse_ntp(lines):
    """Parse `ntp server <ip-or-hostname> [source <if>] [prefer]` lines.
    FTD's NTP object (confirmed via live GET) is just `enabled` + a flat
    `ntpServers` list of strings -- no per-server field for ASA's `source
    <interface>` or `prefer`. `source` has nothing to map to and is only
    recorded here for migrate_ntp.py to print as a heads-up; `prefer` is
    approximated by sorting preferred server(s) first in the list (the
    closest available approximation, not confirmed to affect FTD's actual
    behavior). Other `ntp ...` subcommands (`ntp authenticate`, `ntp
    trusted-key`, `ntp authentication-key`) aren't handled -- there's no
    corresponding field in the confirmed schema either -- and are recorded
    as unparsed rather than silently dropped."""
    servers = []
    unparsed = []
    for line in lines:
        if _indent(line) != 0 or not line.startswith("ntp "):
            continue
        m = _NTP_SERVER_RE.match(line)
        if not m:
            unparsed.append(line)
            continue
        address, rest = m.group(1), m.group(2)
        tokens = rest.split()
        source_interface = None
        if "source" in tokens:
            idx = tokens.index("source")
            if idx + 1 < len(tokens):
                source_interface = tokens[idx + 1]
        servers.append({
            "address": address,
            "prefer": "prefer" in tokens,
            "source_interface": source_interface,
        })
    servers.sort(key=lambda s: not s["prefer"])
    return {"servers": servers}, unparsed


# --------------------------------------------------------------- name aliases
_NAME_ALIAS_RE = re.compile(r"^name (\S+) (\S+)")


def parse_name_aliases(lines):
    """`name <ip> <alias>` -> {alias: ip}. Shared by normalize_asa_config.py
    and by parsers below that need to resolve an alias used in place of a
    literal IP (ASA allows this virtually anywhere an address is expected)."""
    aliases = {}
    for line in lines:
        m = _NAME_ALIAS_RE.match(line)
        if m:
            aliases[m.group(2)] = m.group(1)
    return aliases


# --------------------------------------------------------------- logging
_LOGGING_FROM_ADDRESS_RE = re.compile(r"^logging from-address (\S+)$")
_LOGGING_FTP_SERVER_RE = re.compile(r"^logging ftp-server (\S+) (\S+) (\S+) (\S+)$")


def parse_logging(lines):
    """Parse `logging from-address <email>` (sender address for ASA's
    email-based logging) and `logging ftp-server <host> <path> <username>
    <password>` (periodic FTP archival of the local log buffer) -- two
    unrelated legacy ASA logging destinations that happen to share the
    `logging` command family. Everything else under `logging` (enable,
    timestamps, buffer-size, per-message severity overrides, syslog
    servers, etc.) is deliberately out of scope here.

    The FTP password is returned separately from the main dict so
    parse_asa_config.py can write it to its own gitignored secrets file,
    the same treatment VPN pre-shared keys and SNMP community strings get.
    """
    from_address = None
    ftp_server = None
    password = None
    for line in lines:
        if _indent(line) != 0:
            continue
        m = _LOGGING_FROM_ADDRESS_RE.match(line)
        if m:
            from_address = m.group(1)
            continue
        m = _LOGGING_FTP_SERVER_RE.match(line)
        if m:
            host, path, username, password = m.groups()
            ftp_server = {"host": host, "path": path, "username": username}
    return {"from_address": from_address, "ftp_server": ftp_server}, password


# --------------------------------------------------------------- ICMP control-plane
_ICMP_ANY_RE = re.compile(r"^icmp (permit|deny) any (\S+)$")
_ICMP_HOST_RE = re.compile(r"^icmp (permit|deny) host (\S+) (\S+)$")
_ICMP_NET_RE = re.compile(r"^icmp (permit|deny) (\S+) (\S+) (\S+)$")


def parse_icmp_control(lines, aliases):
    """Parse the ICMP control-plane access list (`icmp permit`/`icmp deny`)
    -- which hosts/networks may send ICMP to the firewall's own interfaces.
    This is unrelated to through-traffic ACLs (there's no `access-list`
    involved at all). Entries are returned in file order, since ASA
    evaluates them top-to-bottom, first match wins -- a `deny` entry
    followed by more `permit` entries for the same interface makes those
    later entries unreachable, which is a real, not-uncommon leftover in
    hand-edited configs. This parser doesn't try to detect or fix that,
    just preserves order so it's visible to whoever reviews the output.

    `icmp unreachable rate-limit ...` (a separate global rate-limiting
    setting, not part of the permit/deny list) is deliberately not handled
    here. Any alias in the network/host position (ASA allows this anywhere
    an address is expected) is resolved to its literal IP via `aliases`."""
    entries = []
    unparsed = []
    for line in lines:
        if _indent(line) != 0 or not line.startswith("icmp "):
            continue
        if line.startswith("icmp unreachable"):
            continue
        m = _ICMP_ANY_RE.match(line)
        if m:
            entries.append({"action": m.group(1).upper(), "subType": "ANY",
                             "value": None, "interface": m.group(2)})
            continue
        m = _ICMP_HOST_RE.match(line)
        if m:
            action, host, interface = m.groups()
            entries.append({"action": action.upper(), "subType": "HOST",
                             "value": aliases.get(host, host), "interface": interface})
            continue
        m = _ICMP_NET_RE.match(line)
        if m:
            action, net, mask, interface = m.groups()
            net = aliases.get(net, net)
            entries.append({"action": action.upper(), "subType": "NETWORK",
                             "value": f"{net}/{_mask_to_prefix(mask)}", "interface": interface})
            continue
        unparsed.append(line)
    return entries, unparsed


# --------------------------------------------------------------- HTTPS management access
_HTTP_ACCESS_RE = re.compile(r"^http (\S+) (\S+) (\S+)$")


def parse_http_management(lines, aliases):
    """Parse `http server enable` and `http <net-or-alias> <mask>
    <interface>` -- ASA's HTTPS/ASDM management access list (which
    networks may reach the device's own management interface, per
    interface). Any alias in the network position is resolved to its
    literal IP via `aliases`."""
    enabled = False
    entries = []
    unparsed = []
    for line in lines:
        if _indent(line) != 0 or not line.startswith("http "):
            continue
        if line == "http server enable":
            enabled = True
            continue
        m = _HTTP_ACCESS_RE.match(line)
        if not m:
            unparsed.append(line)
            continue
        net, mask, interface = m.groups()
        entries.append({
            "value": aliases.get(net, net),
            "mask": mask,
            "interface": interface,
        })
    return {"enabled": enabled, "entries": entries}, unparsed


# --------------------------------------------------------------- SSH management access
_SSH_ACCESS_RE = re.compile(r"^ssh (\S+) (\S+) (\S+)$")


def parse_ssh_management(lines, aliases):
    """Parse `ssh <net-or-alias> <mask> <interface>` -- ASA's SSH management
    access list (which networks may reach the device's own management
    interface via SSH, per interface). Unlike `http server enable`, ASA has
    no separate SSH on/off toggle line -- presence of `ssh` entries is what
    enables it. Any alias in the network position is resolved to its
    literal IP via `aliases`, same as parse_http_management()."""
    entries = []
    unparsed = []
    for line in lines:
        if _indent(line) != 0 or not line.startswith("ssh "):
            continue
        m = _SSH_ACCESS_RE.match(line)
        if not m:
            unparsed.append(line)
            continue
        net, mask, interface = m.groups()
        entries.append({
            "value": aliases.get(net, net),
            "mask": mask,
            "interface": interface,
        })
    return {"entries": entries}, unparsed
