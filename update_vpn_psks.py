#!/usr/bin/env python3
"""
One-off: update the pre-shared keys on S2S VPN connection profiles that
already exist on the FTD (created earlier with vpn_secrets.yaml's `cisco`
placeholder, before the real keys were known).

migrate_s2s_vpn.py's create_or_reuse() only reuses an existing profile by
name -- it never updates one -- so simply re-running it after updating
vpn_secrets.yaml does nothing live. This script GETs each existing
`stosconnectionprofile`, matches it to vpn_secrets.yaml by
`remotePeerIpAddress`, and PUTs the corrected `ikev1PreSharedKey` /
`ikev2LocalPreSharedKey` / `ikev2RemotePreSharedKey` fields -- respecting
whichever of `ikev1Enabled`/`ikev2Enabled` the profile already has, same as
migrate_s2s_vpn.py did when it first created the profile.

Never prints key values themselves -- only which fields changed, per peer.

Usage:
    python update_vpn_psks.py --config config.yaml --secrets-file vpn_secrets.yaml
"""
import argparse

from common.fdm_client import load_config, build_client, FdmApiError
from common.secrets_store import load_vpn_secrets

S2SVPN_PATH = "devices/default/s2sconnectionprofiles"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--secrets-file", default="vpn_secrets.yaml")
    args = ap.parse_args()

    cfg = load_config(args.config)
    client = build_client(cfg)
    secrets_by_peer = load_vpn_secrets(args.secrets_file)

    path = client.resolve_endpoint(S2SVPN_PATH, ["s2s", "connection"])
    profiles = client.get_all_pages(path)
    print(f"Found {len(profiles)} S2S connection profile(s) on the device.")

    updated, unchanged, no_secret, errors = [], [], [], []
    for profile in profiles:
        peer = profile.get("remotePeerIpAddress")
        if not peer:
            continue
        psks = secrets_by_peer.get(peer)
        if not psks:
            no_secret.append(peer)
            continue

        body = dict(profile)
        body.pop("links", None)
        changed_fields = []

        if body.get("ikev1Enabled"):
            new_val = psks.get("ikev1_psk")
            if new_val and body.get("ikev1PreSharedKey") != new_val:
                body["ikev1PreSharedKey"] = new_val
                changed_fields.append("ikev1")
        if body.get("ikev2Enabled"):
            new_local = psks.get("ikev2_local_psk")
            new_remote = psks.get("ikev2_remote_psk")
            if new_local and body.get("ikev2LocalPreSharedKey") != new_local:
                body["ikev2LocalPreSharedKey"] = new_local
                changed_fields.append("ikev2-local")
            if new_remote and body.get("ikev2RemotePreSharedKey") != new_remote:
                body["ikev2RemotePreSharedKey"] = new_remote
                changed_fields.append("ikev2-remote")

        if not changed_fields:
            unchanged.append(peer)
            continue

        try:
            client.put(f"{path}/{profile['id']}", body)
            print(f"  + updated {peer}: {', '.join(changed_fields)}")
            updated.append(peer)
        except FdmApiError as e:
            print(f"  ! failed to update {peer}: {e}")
            errors.append(peer)

    print(f"\nUpdated {len(updated)}, already matched {len(unchanged)}, "
          f"no secret found for {len(no_secret)}, failed {len(errors)}.")
    if no_secret:
        print(f"  no vpn_secrets.yaml entry for: {no_secret}")
    if errors:
        print(f"  failed: {errors}")
    print("\nChanges are staged as pending in FDM -- deploy by hand or via "
          "migrate_s2s_vpn.py's deploy prompt.")


if __name__ == "__main__":
    main()
