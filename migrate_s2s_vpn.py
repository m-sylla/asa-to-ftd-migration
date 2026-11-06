#!/usr/bin/env python3
"""
Push ASA policy-based (crypto-map) site-to-site VPN tunnels, parsed by
parse_asa_config.py, into FTD via the FDM REST API: IKE policies, IPsec
proposals, and site-to-site connection profiles.

Usage:
    python migrate_s2s_vpn.py --config config.yaml --in-dir parsed/

Pre-shared keys are read from vpn_secrets.yaml (project root, not under
--in-dir), keyed by peer IP -- kept separate from parsed/vpn.json so secrets
don't ride along with structural VPN data. Like config.yaml, it's excluded
from git by name.

Object model/field names below were confirmed against a live FTD 7.6.x box
(GET output from /#/api-explorer for stosconnectionprofile, ikev1policies,
ikev2policies, ikev1proposals, ikev2proposals), not guessed -- but enum
values for encryption/hash/DH-group combinations you don't already have an
example of (e.g. an unusual cipher) are still inferred from the ones that
were confirmed, so double check ENCRYPTION_MAP / HASH_MAP / the *_PROPOSAL
maps below against your own /#/api-explorer if a create call gets rejected.

Only IKEv1/IKEv2 with pre-shared-key auth is supported (ASA's most common
L2L setup); certificate-based auth and route-based/VTI VPN are not handled.
IKE policies (Phase 1) are global on FTD, same as on ASA -- they are created
once, not attached per-tunnel; a connection profile only carries its Phase 2
(IPsec) proposal references. Pre-shared keys are read from the ASA config in
cleartext (type 6/8 password encryption is not reversed) -- rotate them
after cutover since they were sitting in a config file.

NAT exemption (so VPN traffic isn't translated) is just one field on this
same object, confirmed against a live device: `interfaceForNatExempt` is
null when disabled, or a reference to the internal/real-side interface when
enabled -- scoped by this profile's own localNetworks/remoteNetworks, no
separate NAT rule object needed. parse_asa_config.py already determines, per
tunnel, whether the ASA had a matching manual/twice-NAT identity rule for
this traffic (`tunnel["nat_exempt"]` / `nat_exempt_interface` in vpn.json);
this script just carries that through.
"""
import argparse
import json
import os

from common.fdm_client import load_config, build_client, FdmApiError
from common.net_helpers import get_or_create_network, classify_cidr_or_range, NETWORKS_PATH
from common.secrets_store import load_vpn_secrets

IKEV1_POLICY_PATH = "object/ikev1policies"
IKEV2_POLICY_PATH = "object/ikev2policies"
IKEV1_PROPOSAL_PATH = "object/ikev1proposals"
IKEV2_PROPOSAL_PATH = "object/ikev2proposals"
S2SVPN_PATH = "devices/default/s2sconnectionprofiles"
INTERFACES_PATH = "devices/default/interfaces"

DEFAULT_IPSEC_LIFETIME_SECONDS = 28800   # ASA default for `set security-association lifetime seconds`
DEFAULT_IPSEC_LIFETIME_KB = 4608000       # ASA default for `set security-association lifetime kilobytes`
DEFAULT_PFS_GROUP = "GROUP14"             # used only when ASA had no `set pfs` and one is required anyway

# ASA "encryption"/"hash"/"group" tokens (crypto ikev1|ikev2 policy) -> FDM
# ikev1policy.encryptionType / ikev2policy.encryptionTypes enum values.
IKE_ENCRYPTION_MAP = {
    "des": "DES", "3des": "THREE_DES", "aes": "AES", "aes-128": "AES",
    "aes-192": "AES192", "aes-256": "AES256",
    "aes-gcm": "AES_GCM", "aes-gcm-192": "AES_GCM192", "aes-gcm-256": "AES_GCM256",
    "null": "NULL",
}
HASH_MAP = {
    "md5": "MD5", "sha": "SHA", "sha1": "SHA", "sha-1": "SHA",
    "sha256": "SHA256", "sha-256": "SHA256", "sha384": "SHA384", "sha-384": "SHA384",
    "sha512": "SHA512", "sha-512": "SHA512", "null": "NULL",
}
DH_GROUP_MAP = {
    "2": "GROUP2", "5": "GROUP5", "14": "GROUP14", "15": "GROUP15", "16": "GROUP16",
    "19": "GROUP19", "20": "GROUP20", "21": "GROUP21", "24": "GROUP24",
    "group2": "GROUP2", "group5": "GROUP5", "group14": "GROUP14", "group15": "GROUP15",
    "group16": "GROUP16", "group19": "GROUP19", "group20": "GROUP20", "group21": "GROUP21",
    "group24": "GROUP24",
}

# Confirmed live rejections (not guesses): this build runs in a "strong
# encryption" / crypto-restricted mode that hard-rejects certain weak
# algorithms outright, and separately enforces which DH groups are usable in
# which context. Different contexts, different disallowed sets.
IKEV1_POLICY_DISALLOWED_DH = {"1", "2"}
IKEV2_POLICY_DISALLOWED_DH = {"1", "2", "24"}
# NOTE: a live 422 rejecting GROUP24 for PFS returns the error text "The
# following Diffie-Hellman groups can no longer be used for Perfect Forward
# Secrecy: 1, 2, 5, 24" -- that message is misleading. A direct live test
# (PUT diffieHellmanGroup: "GROUP5" on a real connection profile) succeeded
# with no error at all, while the same test with "GROUP24" failed with the
# message above. So group 5 is genuinely fine for PFS on this build despite
# what that error text claims; only 1, 2, and 24 are actually enforced.
PFS_DISALLOWED_DH = {"1", "2", "24"}


def _dh_group_digits(raw):
    """'group24' / 'GROUP24' / '24' -> '24', for comparing against the
    disallowed-group sets above regardless of which form ASA used."""
    return raw.lower().replace("group", "").strip() if raw else None

# ASA `crypto ipsec ikev1 transform-set` tokens -> ikev1proposal enum values
# (these carry an ESP_ prefix, unlike the phase-1 policy encryption above).
IKEV1_PROPOSAL_ENCRYPTION_MAP = {
    # Confirmed against a live 422 error's declared enum list: [ESP_AES256,
    # ESP_AES, ESP_NULL, ESP_DES, ESP_AES192, ESP_3DES] -- no GCM variants
    # exist for this object type on this build.
    "esp-des": "ESP_DES", "esp-3des": "ESP_3DES", "esp-aes": "ESP_AES",
    "esp-aes-192": "ESP_AES192", "esp-aes-256": "ESP_AES256", "esp-null": "ESP_NULL",
}
IKEV1_PROPOSAL_AUTH_MAP = {
    "esp-md5-hmac": "ESP_MD5_HMAC", "esp-sha-hmac": "ESP_SHA_HMAC",
    "esp-sha256-hmac": "ESP_SHA256_HMAC", "esp-sha384-hmac": "ESP_SHA384_HMAC",
    "esp-sha512-hmac": "ESP_SHA512_HMAC", "esp-none": "ESP_NONE",
}


def map_token(table, token, kind):
    if not token:
        return None
    key = token.lower()
    if key in table:
        return table[key]
    print(f"  ! no mapping for {kind} token '{token}', passing through uppercased -- "
          f"verify this is a valid enum value in /#/api-explorer for your FTD build")
    return token.upper()


def find_interface_ref(client, iface_path, logical_name):
    interfaces = client.get_all_pages(iface_path)
    for iface in interfaces:
        if iface.get("name") == logical_name or iface.get("hardwareName") == logical_name:
            return {"id": iface["id"], "type": iface.get("type", "physicalinterface")}
    return None


PRIORITY_COLLISION_OFFSET = 1000  # bump by this and retry once if priority collides with an existing policy


def _create_policy_with_priority_retry(client, path, body, skip_existing, label):
    try:
        client.create_or_reuse(path, body, skip_existing)
        return
    except FdmApiError as e:
        msg = str(e).lower()
        if "overlap with existing policy" not in msg and "samepriority" not in msg:
            print(f"  ! failed to create {label}: {e}")
            return
        bumped = body["priority"] + PRIORITY_COLLISION_OFFSET
        print(f"  ! {label}'s priority {body['priority']} collides with an existing policy "
              f"(likely one of FTD's built-in defaults) -- retrying at priority {bumped}")
        body = dict(body, priority=bumped)
        try:
            client.create_or_reuse(path, body, skip_existing)
        except FdmApiError as e2:
            print(f"  ! failed to create {label} even at priority {bumped}: {e2}")


def _existing_values(client, path, value_keys, require_enabled=True):
    """{value tuple: name} for every existing object at `path` (only the
    enabled ones when `require_enabled`), so a new object whose value
    combination already exists under a different name can be skipped instead
    of creating a functionally duplicate one. Two confirmed live platform
    limits motivate this: total *enabled* IKEv2 policies capped at 20, and
    total ipsec-proposals (IKEv1 and IKEv2 each) capped at 20 -- a device
    with 41 IKEv2 proposals backing only ~3 distinct crypto combinations (one
    tunnel-specific proposal per tunnel, named after the tunnel, even when
    two tunnels use identical encryption/integrity) blew straight through
    that ceiling at deploy time ("the maximum proposal limit of 20 was
    exceeded"), even though every individual POST had succeeded. Proposals
    have no `enabled` field (every existing one counts against the cap
    regardless), hence `require_enabled=False` for those callers."""
    if client.dry_run:
        return {}
    existing = {}
    for p in client.get_all_pages(path):
        if require_enabled and not p.get("enabled"):
            continue
        key = tuple(tuple(v) if isinstance(v, list) else v for v in
                     (p.get(k) for k in value_keys))
        existing.setdefault(key, p.get("name"))
    return existing


def create_ike_policies(client, vpn_data, skip_existing):
    """IKE (Phase 1) policies are global on FTD, same as ASA's `crypto ikev1|ikev2
    policy` -- create/enable them once, they are not referenced per-connection."""
    ikev1_path = client.resolve_endpoint(IKEV1_POLICY_PATH, ["ikev1", "polic"])
    ikev2_path = client.resolve_endpoint(IKEV2_POLICY_PATH, ["ikev2", "polic"])

    ikev1_value_keys = ("encryptionType", "hashType", "groupType", "lifeTime")
    ikev2_value_keys = ("encryptionTypes", "integrityTypes", "groupTypes", "prfTypes", "lifeTime")
    existing_ikev1_values = _existing_values(client, ikev1_path, ikev1_value_keys)
    existing_ikev2_values = _existing_values(client, ikev2_path, ikev2_value_keys)

    for prio, pol in vpn_data["ikev1_policies"].items():
        if _dh_group_digits(pol.get("dh_group")) in IKEV1_POLICY_DISALLOWED_DH:
            print(f"  ! ASA IKEv1 policy {prio} uses DH group {pol['dh_group']}, which this "
                  f"FTD build rejects outright for IKEv1 policies (deprecated/too weak) -- "
                  f"skipping. If this group is still needed for a legacy peer, it needs "
                  f"hand-configuring with a fallback the device will accept.")
            continue
        body = {
            "name": f"ASA_IKEV1_POLICY_{prio}",
            "type": "ikevonepolicy",
            "enabled": True,
            "priority": int(prio),
            "lifeTime": pol.get("lifetime_seconds", 86400),
            "authenticationType": "PRE_SHARED_KEY",
            "encryptionType": map_token(IKE_ENCRYPTION_MAP, pol.get("encryption"), "ikev1 policy encryption"),
            "hashType": map_token(HASH_MAP, pol.get("hash"), "ikev1 policy hash"),
            "groupType": map_token(DH_GROUP_MAP, pol.get("dh_group"), "ikev1 policy DH group"),
        }
        value_key = tuple(body[k] for k in ikev1_value_keys)
        dup_name = existing_ikev1_values.get(value_key)
        if dup_name:
            print(f"  = ASA IKEv1 policy {prio} has the same encryption/hash/group/lifetime "
                  f"as already-enabled '{dup_name}' -- skipping, it's already covered")
            continue
        _create_policy_with_priority_retry(client, ikev1_path, body, skip_existing,
                                            f"IKEv1 policy {prio}")
        existing_ikev1_values[value_key] = body["name"]
    for prio, pol in vpn_data["ikev2_policies"].items():
        if (pol.get("encryption") or "").lower() == "des":
            print(f"  ! ASA IKEv2 policy {prio} uses DES encryption, which this FTD build "
                  f"rejects outright in strong-encryption mode -- skipping.")
            continue
        if _dh_group_digits(pol.get("dh_group")) in IKEV2_POLICY_DISALLOWED_DH:
            print(f"  ! ASA IKEv2 policy {prio} uses DH group {pol.get('dh_group')}, which "
                  f"this FTD build rejects outright for IKEv2 policies -- skipping.")
            continue
        body = {
            "name": f"ASA_IKEV2_POLICY_{prio}",
            "type": "ikevtwopolicy",
            "enabled": True,
            "priority": int(prio),
            "lifeTime": pol.get("lifetime_seconds", 86400),
            "encryptionTypes": [map_token(IKE_ENCRYPTION_MAP, pol.get("encryption"), "ikev2 policy encryption")],
            "integrityTypes": [map_token(HASH_MAP, pol.get("integrity"), "ikev2 policy integrity")],
            "groupTypes": [map_token(DH_GROUP_MAP, pol.get("dh_group"), "ikev2 policy DH group")],
            "prfTypes": [map_token(HASH_MAP, pol.get("prf"), "ikev2 policy prf")],
        }
        value_key = tuple(tuple(body[k]) if isinstance(body[k], list) else body[k]
                           for k in ikev2_value_keys)
        dup_name = existing_ikev2_values.get(value_key)
        if dup_name:
            print(f"  = ASA IKEv2 policy {prio} has the same encryption/integrity/group/prf/"
                  f"lifetime as already-enabled '{dup_name}' -- skipping, it's already covered "
                  f"(FTD caps enabled IKEv2 policies at 20 -- confirmed live -- so redundant "
                  f"ones aren't just clutter, they can push a device over that limit at deploy)")
            continue
        _create_policy_with_priority_retry(client, ikev2_path, body, skip_existing,
                                            f"IKEv2 policy {prio}")
        existing_ikev2_values[value_key] = body["name"]


def create_ikev1_proposal(client, tunnel, skip_existing, existing_values):
    tokens = tunnel.get("ikev1_transform_set")
    if not tokens:
        return None
    path = client.resolve_endpoint(IKEV1_PROPOSAL_PATH, ["ikev1", "proposal"])
    enc_tok = next((t for t in tokens if "hmac" not in t), None)
    auth_tok = next((t for t in tokens if "hmac" in t), None)
    encryption_method = map_token(IKEV1_PROPOSAL_ENCRYPTION_MAP, enc_tok, "ikev1 transform-set encryption")
    auth_method = map_token(IKEV1_PROPOSAL_AUTH_MAP, auth_tok, "ikev1 transform-set auth")

    value_key = (encryption_method, auth_method)
    dup_name = existing_values.get(value_key)
    if dup_name:
        existing = client.find_by_name(path, dup_name) if not client.dry_run else None
        if existing:
            return {"id": existing["id"], "type": "ikevoneproposal"}

    body = {
        "name": f"ASA_TS_{tunnel['crypto_map']}_{tunnel['seq']}",
        "type": "ikevoneproposal",
        "encryptionMethod": encryption_method,
        "authenticationMethod": auth_method,
        "mode": "TUNNEL",
    }
    created = client.create_or_reuse(path, body, skip_existing)
    existing_values[value_key] = created.get("name", body["name"])
    return {"id": created["id"], "type": "ikevoneproposal"}


def create_ikev2_proposal(client, tunnel, skip_existing, existing_values):
    prop = tunnel.get("ikev2_proposal")
    if not prop:
        return None
    path = client.resolve_endpoint(IKEV2_PROPOSAL_PATH, ["ikev2", "proposal"])
    enc_tokens = [e for e in prop.get("encryption", []) if e.lower() != "des"]
    if len(enc_tokens) != len(prop.get("encryption", [])):
        print(f"  ! ASA ikev2 ipsec-proposal for tunnel to {tunnel.get('peer')} offered DES, "
              f"which this FTD build rejects outright in strong-encryption mode -- dropping "
              f"just that option, keeping the rest of the offered ciphers.")
    if not enc_tokens:
        print(f"  ! ikev2 ipsec-proposal for tunnel to {tunnel.get('peer')} offered only DES "
              f"encryption, which this FTD build won't accept at all -- no usable IKEv2 "
              f"proposal for this tunnel.")
        return None
    encryption_types = [map_token(IKE_ENCRYPTION_MAP, e, "ikev2 proposal encryption") for e in enc_tokens]
    integrity_types = [map_token(HASH_MAP, i, "ikev2 proposal integrity") for i in prop.get("integrity", [])]

    value_key = (tuple(encryption_types), tuple(integrity_types))
    dup_name = existing_values.get(value_key)
    if dup_name:
        existing = client.find_by_name(path, dup_name) if not client.dry_run else None
        if existing:
            return {"id": existing["id"], "type": "ikevtwoproposal"}

    body = {
        "name": f"ASA_PROP_{tunnel['crypto_map']}_{tunnel['seq']}",
        "type": "ikevtwoproposal",
        "encryptionTypes": encryption_types,
        "integrityTypes": integrity_types,
    }
    created = client.create_or_reuse(path, body, skip_existing)
    existing_values[value_key] = created.get("name", body["name"])
    return {"id": created["id"], "type": "ikevtwoproposal"}


def networks_to_refs(client, net_path, cidrs, skip_existing):
    refs = []
    for cidr in cidrs:
        if cidr.startswith("UNRESOLVED") or cidr.startswith("OBJECT:"):
            print(f"    ! skipping unresolved network reference '{cidr}' -- add it to the "
                  f"tunnel's protected networks manually in FDM")
            continue
        sub_type, value = classify_cidr_or_range(cidr)
        refs.append(get_or_create_network(client, net_path, value, sub_type, skip_existing))
    return refs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--in-dir", default="parsed")
    ap.add_argument("--secrets-file", default="vpn_secrets.yaml",
                     help="File holding VPN pre-shared keys, keyed by peer IP "
                          "(default: vpn_secrets.yaml in the current directory)")
    args = ap.parse_args()

    cfg = load_config(args.config)
    skip_existing = cfg.get("options", {}).get("skip_existing", True)
    iface_map = cfg.get("interface_map", {})
    client = build_client(cfg)

    with open(os.path.join(args.in_dir, "vpn.json")) as f:
        vpn_data = json.load(f)
    secrets_by_peer = load_vpn_secrets(args.secrets_file)

    net_path = client.resolve_endpoint(NETWORKS_PATH, ["network"])
    iface_path = client.resolve_endpoint(INTERFACES_PATH, ["interfaces"])
    s2s_path = client.resolve_endpoint(S2SVPN_PATH, ["s2s", "connection"])
    ikev1_proposal_path = client.resolve_endpoint(IKEV1_PROPOSAL_PATH, ["ikev1", "proposal"])
    ikev2_proposal_path = client.resolve_endpoint(IKEV2_PROPOSAL_PATH, ["ikev2", "proposal"])

    print(f"Creating global IKE policies ({len(vpn_data['ikev1_policies'])} IKEv1, "
          f"{len(vpn_data['ikev2_policies'])} IKEv2)...")
    create_ike_policies(client, vpn_data, skip_existing)

    # Proposals are created per-tunnel but have no `enabled` field of their
    # own -- every existing one counts against FTD's confirmed-live 20-max
    # ipsec-proposal limit, so dedupe by value across all tunnels sharing
    # this run, not just within a single tunnel (see _existing_values()).
    existing_ikev1_proposal_values = _existing_values(
        client, ikev1_proposal_path, ("encryptionMethod", "authenticationMethod"), require_enabled=False)
    existing_ikev2_proposal_values = _existing_values(
        client, ikev2_proposal_path, ("encryptionTypes", "integrityTypes"), require_enabled=False)

    created = 0
    for tunnel in vpn_data["tunnels"]:
        peer = tunnel.get("peer")
        if not peer:
            print(f"  ! crypto map {tunnel['crypto_map']} seq {tunnel['seq']} has no peer, skipping")
            continue
        ftd_iface_name = iface_map.get(tunnel["interface"])
        if not ftd_iface_name:
            print(f"  ! no interface_map entry for ASA nameif '{tunnel['interface']}', "
                  f"skipping tunnel to {peer}")
            continue
        if client.dry_run:
            iface_ref = {"id": f"dryrun-iface-{ftd_iface_name}", "type": "physicalinterface"}
        else:
            iface_ref = find_interface_ref(client, iface_path, ftd_iface_name)
            if not iface_ref:
                print(f"  ! FTD interface '{ftd_iface_name}' not found, skipping tunnel to {peer}")
                continue

        print(f"Building tunnel to {peer} (crypto map {tunnel['crypto_map']} seq {tunnel['seq']})...")
        try:
            local_refs = networks_to_refs(client, net_path, tunnel["local_networks"], skip_existing)
            remote_refs = networks_to_refs(client, net_path, tunnel["remote_networks"], skip_existing)
            ikev1_proposal_ref = create_ikev1_proposal(
                client, tunnel, skip_existing, existing_ikev1_proposal_values)
            ikev2_proposal_ref = create_ikev2_proposal(
                client, tunnel, skip_existing, existing_ikev2_proposal_values)
        except FdmApiError as e:
            print(f"  ! failed to resolve networks/proposals for tunnel to {peer}: {e}")
            continue
        if not ikev1_proposal_ref and not ikev2_proposal_ref:
            print(f"  ! no IKEv1 transform-set or IKEv2 ipsec-proposal resolved for tunnel "
                  f"to {peer}, skipping")
            continue

        psks = secrets_by_peer.get(peer, {})
        ikev1_enabled = ikev1_proposal_ref is not None
        ikev2_enabled = ikev2_proposal_ref is not None
        if ikev1_enabled and not psks.get("ikev1_psk"):
            print(f"  ! no IKEv1 pre-shared key found for tunnel to {peer} in "
                  f"{args.secrets_file} -- set it manually in FDM")
        if ikev2_enabled and not (psks.get("ikev2_local_psk") or psks.get("ikev2_remote_psk")):
            print(f"  ! no IKEv2 pre-shared key found for tunnel to {peer} in "
                  f"{args.secrets_file} -- set it manually in FDM")

        raw_pfs = tunnel.get("pfs_group")
        if raw_pfs and _dh_group_digits(raw_pfs) in PFS_DISALLOWED_DH:
            print(f"  ! ASA config used PFS group {raw_pfs} for tunnel to {peer}, which this "
                  f"FTD build no longer accepts for PFS -- substituting {DEFAULT_PFS_GROUP}")
            pfs_group = DEFAULT_PFS_GROUP
        elif raw_pfs:
            pfs_group = map_token(DH_GROUP_MAP, raw_pfs, "pfs group")
        else:
            print(f"  ! ASA config had no `set pfs` for tunnel to {peer}; defaulting "
                  f"diffieHellmanGroup to {DEFAULT_PFS_GROUP} -- adjust in FDM if PFS "
                  f"should be handled differently")
            pfs_group = DEFAULT_PFS_GROUP

        # NAT exemption on FTD is just this one field on the connection profile
        # (confirmed against a live device: null when disabled, an interface ref
        # -- the internal/real-side interface -- when enabled), scoped by this
        # profile's own localNetworks/remoteNetworks. No separate NAT rule object
        # needed.
        nat_exempt_ref = None
        if tunnel.get("nat_exempt") and tunnel.get("nat_exempt_interface"):
            nat_exempt_asa_iface = tunnel["nat_exempt_interface"]
            nat_exempt_ftd_name = iface_map.get(nat_exempt_asa_iface)
            if not nat_exempt_ftd_name:
                print(f"  ! ASA had a NAT exemption on interface '{nat_exempt_asa_iface}' for "
                      f"tunnel to {peer}, but there's no interface_map entry for it -- "
                      f"NAT exemption will be left disabled, traffic may get translated")
            elif client.dry_run:
                nat_exempt_ref = {"id": f"dryrun-iface-{nat_exempt_ftd_name}", "type": "physicalinterface"}
            else:
                nat_exempt_ref = find_interface_ref(client, iface_path, nat_exempt_ftd_name)
                if not nat_exempt_ref:
                    print(f"  ! FTD interface '{nat_exempt_ftd_name}' not found for NAT "
                          f"exemption on tunnel to {peer}, leaving it disabled")
        elif tunnel.get("local_networks") and tunnel.get("remote_networks"):
            print(f"  ! no NAT exemption found on the ASA for tunnel to {peer} -- leaving "
                  f"it disabled on FTD too (traffic will be translated per your NAT policy, "
                  f"same as on the ASA); check parsed/vpn.json's nat_exempt_uncovered_pairs "
                  f"if this is unexpected")

        body = {
            "name": f"S2S_{peer.replace('.', '-')}",
            "type": "stosconnectionprofile",
            "ikev1Enabled": ikev1_enabled,
            "ikev1AuthMethod": "PRE_SHARED_KEY",
            "ikev1IDCertificate": None,
            "ikev1PreSharedKey": psks.get("ikev1_psk") if ikev1_enabled else None,
            "ikev1Proposals": [ikev1_proposal_ref] if ikev1_proposal_ref else [],
            "ikev2Enabled": ikev2_enabled,
            "ikev2AuthMethod": "PRE_SHARED_KEY",
            "ikev2IDCertificate": None,
            "ikev2LocalPreSharedKey": psks.get("ikev2_local_psk") if ikev2_enabled else None,
            "ikev2RemotePeerPreSharedKey": psks.get("ikev2_remote_psk") if ikev2_enabled else None,
            "ikev2Proposals": [ikev2_proposal_ref] if ikev2_proposal_ref else [],
            "localNetworks": local_refs,
            "remoteNetworks": remote_refs,
            "outsideInterfaces": [iface_ref],
            "rriEnabled": False,
            "dynamicRRIEnabled": False,
            "staticVTIEnabled": False,
            "remotePeerIpAddress": peer,
            "remoteBackupPeers": [],
            "isRemotePeerIpDynamic": False,
            "ipsecLifetimeInSeconds": tunnel.get("lifetime_seconds") or DEFAULT_IPSEC_LIFETIME_SECONDS,
            "ipsecLifetimeInKiloBytes": DEFAULT_IPSEC_LIFETIME_KB,
            "ipsecLifetimeUnlimited": False,
            "diffieHellmanGroup": pfs_group,
            "interfaceForNatExempt": nat_exempt_ref,
            "connectionType": None,
        }
        try:
            client.create_or_reuse(s2s_path, body, skip_existing)
            created += 1
        except FdmApiError as e:
            print(f"  ! failed to create S2S VPN connection for peer {peer}: {e}\n"
                  f"    FDM's validation error above should name the offending field -- "
                  f"cross-check it against https://{client.host}/#/api-explorer and adjust "
                  f"the relevant map/body in migrate_s2s_vpn.py, then re-run (existing "
                  f"objects are reused, not duplicated).")

    print(f"Processed {len(vpn_data['tunnels'])} tunnel definition(s), created/reused {created}.")

    if not client.dry_run:
        deploy = input("Deploy these changes to the device now? [y/N] ").strip().lower()
        if deploy == "y":
            client.deploy()
        else:
            print("Skipped deploy -- VPN config is staged as pending changes in FDM.")


if __name__ == "__main__":
    main()
