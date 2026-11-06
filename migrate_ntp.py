#!/usr/bin/env python3
"""
Push ASA NTP server configuration (parsed by parse_asa_config.py) into FTD
via the FDM REST API.

CONFIRMED against a live FTD 7.6.4 box: `GET devicesettings/default/ntp`
returns a real NTP settings collection -- fields `enabled` (bool),
`description`, `ntpServers` (a flat list of hostname/IP strings), `type:
"ntp"`. ASA's per-server `source <interface>` has no equivalent field in
this schema -- dropped, printed as a heads-up rather than silently lost.
ASA's `prefer` keyword has no equivalent field either; approximated only by
putting that server first in `ntpServers` (parser/asa_parser.py's
parse_ntp() does this ordering) -- not confirmed to affect FTD's actual
behavior, just the closest available approximation.

**Real oddity found on a live device, now resolved by a live PUT attempt on
both**: `GET devicesettings/default/ntp` returned *two* items on a
freshly-restored box, both identical factory defaults (disabled,
`{0,1,2}.sourcefire.pool.ntp.org`) -- `00000004-0000-0000-0000-000000000002`
(the all-zeros-prefixed synthetic ID pattern FTD uses for its real built-in
singletons, same style as DataDNSSettings' `00000013-...`) and
`954f490f-7e76-11e5-bfa4-bbacca2d71bc` (an ordinary-looking UUID). A live
PUT to the first succeeded and was confirmed correct by reading it back
(`enabled: true`, both ASA servers, preferred one first); the same PUT to
the second was rejected outright: `422 invalidUuid` -- "Validation failed
due to an invalid UUID" for an ID the device's own GET just returned. So
the `00000004-...` object is the real, editable one; the other appears to
be a legacy/decoy entry that can't be written to at all. This script still
attempts every item in the collection (rather than hardcoding the specific
id, in case a different device's decoy has a different id) and treats a
per-item failure as informational, not fatal -- confirm in FDM's UI
(Device > NTP) if you want to see this for yourself.

Usage:
    python migrate_ntp.py --config config.yaml --in-dir parsed/
"""
import argparse
import json
import os

from common.fdm_client import load_config, build_client, FdmApiError

NTP_SETTINGS_PATH = "devicesettings/default/ntp"


def push_ntp(client, ntp_data):
    servers = [s["address"] for s in ntp_data["servers"]]
    for s in ntp_data["servers"]:
        if s.get("source_interface"):
            flags = " prefer" if s["prefer"] else ""
            print(f"  i ASA 'ntp server {s['address']} source {s['source_interface']}"
                  f"{flags}' -- source-interface has no FTD field, dropped (the server "
                  f"itself is still migrated)")

    if not servers:
        print("  ! no NTP servers parsed -- nothing to push")
        return 0

    path = client.resolve_endpoint(NTP_SETTINGS_PATH, ["ntp"])
    if client.dry_run:
        items = [{"id": "dryrun-ntp-1", "type": "ntp", "enabled": False,
                  "ntpServers": [], "description": None}]
    else:
        try:
            items = client.get_all_pages(path)
        except FdmApiError as e:
            print(f"  ! could not read current NTP settings ({e}) -- skipping, set NTP "
                  f"servers by hand in FDM (Device > NTP) if needed")
            return 0
        if not items:
            print("  ! no NTP settings object found -- skipping")
            return 0
        if len(items) > 1:
            print(f"  i found {len(items)} NTP settings objects on this device -- "
                  f"attempting all of them (confirmed on one real device: only the "
                  f"all-zeros-prefixed id was actually writable, the other was rejected "
                  f"with 'invalid UUID' -- see module docstring)")

    updated = 0
    for existing in items:
        body = dict(existing)
        body.pop("links", None)
        body["enabled"] = True
        body["ntpServers"] = servers
        try:
            client.put(f"{path}/{existing['id']}", body)
            print(f"  + updated NTP settings {existing['id']} with {len(servers)} server(s)")
            updated += 1
        except FdmApiError as e:
            print(f"  ! failed to update NTP settings {existing['id']}: {e}")
    return updated


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--in-dir", default="parsed")
    args = ap.parse_args()

    cfg = load_config(args.config)
    client = build_client(cfg)

    with open(os.path.join(args.in_dir, "ntp.json")) as f:
        ntp_data = json.load(f)

    print(f"Pushing {len(ntp_data['servers'])} NTP server(s)...")
    updated = push_ntp(client, ntp_data)
    print(f"Updated {updated} NTP settings object(s).")

    if not cfg.get("options", {}).get("dry_run", True):
        deploy = input("Deploy these changes to the device now? [y/N] ").strip().lower()
        if deploy == "y":
            client.deploy()
        else:
            print("Skipped deploy -- NTP config is staged as pending changes in FDM.")


if __name__ == "__main__":
    main()
