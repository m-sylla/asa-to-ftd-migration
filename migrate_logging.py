#!/usr/bin/env python3
"""
Report ASA's `logging from-address` and `logging ftp-server` settings
(parsed by parse_asa_config.py). Unlike every other migrate_*.py script
here, this one does NOT attempt a live push by default.

Why: `from-address` configures the sender address for ASA's email-based
logging (`logging mail <priority>`), and `ftp-server` configures periodic
FTP archival of the local log buffer -- both legacy ASA-specific log
destinations.

**`ftp-server` is confirmed NOT supported on FTD/FDM** -- there is no FTP
log-archival destination in FDM's logging model at all, not merely an
unconfirmed field name. This is a real feature gap, not something this
script can push around: if you need the ASA's local log buffer archived
somewhere, that has to be replaced with a different mechanism entirely
(e.g. an external syslog server / SIEM), not a like-for-like migration.

`from-address` (email-based logging) is unconfirmed either way -- FTD's
logging model is built around local event storage plus external syslog
(and, for FMC-managed deployments, sending events to FMC), and it isn't
obvious an "email the log" concept exists on FTD, but this hasn't been
specifically checked the way ftp-server was. If your build does have a
relevant setting (check Device > System Settings > Logging or similar in
FDM, or search API Explorer for "logging"/"syslog"/"mail"), share a live
GET the same way every confirmed endpoint in this toolkit was found, and
this can be extended into a real push the same way
migrate_dns.py/migrate_snmp.py/migrate_ntp.py were.

The FTP password itself is never printed here -- it lives only in
logging_secrets.yaml (gitignored), read but not displayed by this script.

Usage:
    python migrate_logging.py --config config.yaml --in-dir parsed/
"""
import argparse
import json
import os

from common.secrets_store import load_logging_secrets


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in-dir", default="parsed")
    ap.add_argument("--secrets-file", default="logging_secrets.yaml")
    args = ap.parse_args()

    with open(os.path.join(args.in_dir, "logging.json")) as f:
        logging_data = json.load(f)
    has_password = bool(load_logging_secrets(args.secrets_file))

    from_address = logging_data.get("from_address")
    ftp_server = logging_data.get("ftp_server")

    if not from_address and not ftp_server:
        print("No `logging from-address` or `logging ftp-server` found in the ASA config "
              "-- nothing to report.")
        return

    print("ASA logging settings found -- see this script's docstring for why nothing is "
          "pushed automatically:")
    if from_address:
        print(f"  - from-address (email sender for ASA's mail-based logging): {from_address} "
              f"(FTD equivalent unconfirmed)")
    if ftp_server:
        print(f"  - ftp-server: host={ftp_server['host']} path={ftp_server['path']} "
              f"username={ftp_server['username']} "
              f"password={'(in ' + args.secrets_file + ')' if has_password else '(not found)'} "
              f"-- CONFIRMED NOT SUPPORTED on FTD/FDM, no migration path exists for this "
              f"specific mechanism (consider an external syslog server/SIEM instead)")
    print("Configure the equivalent manually in FDM if one exists on your build, or confirm "
          "the relevant API endpoint and this script can be extended to push it directly.")


if __name__ == "__main__":
    main()
