#!/usr/bin/env python3
"""
Parse an ASA `show running-config` text dump into intermediate JSON files
consumed by migrate_network_objects.py, migrate_routes.py and migrate_s2s_vpn.py.

Usage:
    python parse_asa_config.py asa-running-config.txt --out-dir parsed/

Review the generated JSON (especially parsed/unparsed_lines.json and any
"UNRESOLVED"/"OBJECT:" markers in vpn.json) before running the migration
scripts -- this parser covers common ASA 9.12 syntax, not every variant.

VPN pre-shared keys, SNMP community strings, and the logging FTP password are
each written to their own file (vpn_secrets.yaml, snmp_secrets.yaml,
logging_secrets.yaml -- all at the project root, not under --out-dir)
instead of into their structural JSON, so secrets don't ride along with
structural data. Like config.yaml, all three are excluded from git by name
-- see .gitignore.
"""
import argparse
import json
import os

from parser.asa_parser import (
    load_lines, parse_network_objects, parse_object_groups, parse_routes, parse_s2s_vpn,
    parse_nat_rules, parse_auto_nat_rules, check_nat_exemption, parse_dns, parse_snmp, parse_ntp,
    parse_name_aliases, parse_logging, parse_icmp_control, parse_http_management,
    parse_ssh_management,
)
from common.secrets_store import save_vpn_secrets, save_snmp_secrets, save_logging_secrets

PSK_FIELDS = ("ikev1_psk", "ikev2_local_psk", "ikev2_remote_psk")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("config_file", help="Path to ASA 'show running-config' output")
    ap.add_argument("--out-dir", default="parsed")
    ap.add_argument("--secrets-file", default="vpn_secrets.yaml",
                     help="Where to write extracted VPN pre-shared keys (default: "
                          "vpn_secrets.yaml in the current directory)")
    ap.add_argument("--snmp-secrets-file", default="snmp_secrets.yaml",
                     help="Where to write extracted SNMP community strings (default: "
                          "snmp_secrets.yaml in the current directory)")
    ap.add_argument("--logging-secrets-file", default="logging_secrets.yaml",
                     help="Where to write the extracted logging FTP password (default: "
                          "logging_secrets.yaml in the current directory)")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    lines = load_lines(args.config_file)

    objects, unparsed_obj = parse_network_objects(lines)
    groups, unparsed_grp = parse_object_groups(lines)
    routes, unparsed_routes = parse_routes(lines)
    vpn, unparsed_vpn = parse_s2s_vpn(lines, objects, groups)
    nat_rules, unparsed_nat = parse_nat_rules(lines, objects, groups)
    auto_nat_rules = parse_auto_nat_rules(lines, objects)
    check_nat_exemption(vpn["tunnels"], nat_rules)  # annotates each tunnel in place
    dns_data, unparsed_dns = parse_dns(lines)
    snmp_data, snmp_communities, unparsed_snmp = parse_snmp(lines)
    ntp_data, unparsed_ntp = parse_ntp(lines)
    aliases = parse_name_aliases(lines)
    logging_data, ftp_password = parse_logging(lines)
    icmp_entries, unparsed_icmp = parse_icmp_control(lines, aliases)
    http_data, unparsed_http = parse_http_management(lines, aliases)
    ssh_data, unparsed_ssh = parse_ssh_management(lines, aliases)

    # Pull PSKs out of each tunnel into a separate, gitignored file keyed by peer.
    secrets_by_peer = {}
    for tunnel in vpn["tunnels"]:
        peer = tunnel.get("peer")
        keys = {f: tunnel.pop(f, None) for f in PSK_FIELDS}
        if peer and any(keys.values()):
            secrets_by_peer[peer] = keys
    save_vpn_secrets(args.secrets_file, secrets_by_peer)
    save_snmp_secrets(args.snmp_secrets_file, snmp_communities)
    save_logging_secrets(args.logging_secrets_file, ftp_password)

    with open(os.path.join(args.out_dir, "network_objects.json"), "w") as f:
        json.dump({"objects": objects, "groups": groups}, f, indent=2)
    with open(os.path.join(args.out_dir, "routes.json"), "w") as f:
        json.dump(routes, f, indent=2)
    with open(os.path.join(args.out_dir, "vpn.json"), "w") as f:
        json.dump(vpn, f, indent=2)
    with open(os.path.join(args.out_dir, "nat_exemptions.json"), "w") as f:
        json.dump({"rules": nat_rules}, f, indent=2)
    with open(os.path.join(args.out_dir, "auto_nat.json"), "w") as f:
        json.dump({"rules": auto_nat_rules}, f, indent=2)
    with open(os.path.join(args.out_dir, "dns.json"), "w") as f:
        json.dump(dns_data, f, indent=2)
    with open(os.path.join(args.out_dir, "snmp.json"), "w") as f:
        json.dump(snmp_data, f, indent=2)
    with open(os.path.join(args.out_dir, "ntp.json"), "w") as f:
        json.dump(ntp_data, f, indent=2)
    with open(os.path.join(args.out_dir, "logging.json"), "w") as f:
        json.dump(logging_data, f, indent=2)
    with open(os.path.join(args.out_dir, "icmp_control.json"), "w") as f:
        json.dump({"entries": icmp_entries}, f, indent=2)
    with open(os.path.join(args.out_dir, "http_management.json"), "w") as f:
        json.dump(http_data, f, indent=2)
    with open(os.path.join(args.out_dir, "ssh_management.json"), "w") as f:
        json.dump(ssh_data, f, indent=2)

    all_unparsed = (unparsed_obj + unparsed_grp + unparsed_routes + unparsed_vpn
                     + unparsed_nat + unparsed_dns + unparsed_snmp + unparsed_ntp
                     + unparsed_icmp + unparsed_http + unparsed_ssh)
    with open(os.path.join(args.out_dir, "unparsed_lines.json"), "w") as f:
        json.dump(all_unparsed, f, indent=2)

    print(f"Parsed {len(objects)} network objects, {len(groups)} object-groups, "
          f"{len(routes)} static routes, {len(vpn['tunnels'])} site-to-site tunnels, "
          f"{len(nat_rules)} manual NAT rule(s), {len(auto_nat_rules)} auto-NAT rule(s), "
          f"{len(dns_data['server_groups'])} DNS server-group(s), "
          f"{len(snmp_data['hosts'])} SNMP host(s), {len(ntp_data['servers'])} NTP server(s), "
          f"{len(icmp_entries)} ICMP control-plane entry/entries, "
          f"{len(http_data['entries'])} HTTPS management access entry/entries, "
          f"{len(ssh_data['entries'])} SSH management access entry/entries.")
    secrets_written = [f"{len(secrets_by_peer)} tunnel pre-shared key(s) to {args.secrets_file}",
                       f"{len(snmp_communities)} SNMP community string(s) to {args.snmp_secrets_file}"]
    if ftp_password:
        secrets_written.append(f"the logging FTP password to {args.logging_secrets_file}")
    print(f"Wrote {', '.join(secrets_written)} (all gitignored -- keep them out of version control).")
    if all_unparsed:
        print(f"{len(all_unparsed)} line(s) could not be parsed -- see "
              f"{args.out_dir}/unparsed_lines.json")
    unresolved = [t for t in vpn["tunnels"]
                  if any("UNRESOLVED" in n or "OBJECT:" in n
                         for n in t["local_networks"] + t["remote_networks"])]
    if unresolved:
        print(f"{len(unresolved)} tunnel(s) have unresolved network references -- "
              f"check vpn.json before migrating (peers: "
              f"{[t['peer'] for t in unresolved]})")
    not_exempt = [t for t in vpn["tunnels"] if not t["nat_exempt"]]
    if not_exempt:
        print(f"! {len(not_exempt)} tunnel(s) have NO matching NAT exemption found on the "
              f"ASA -- this traffic may get translated unless that's intentional (e.g. an "
              f"identity NAT rule via an object-group this parser couldn't resolve, or NAT "
              f"exemption genuinely isn't configured). Check vpn.json's nat_exempt / "
              f"nat_exempt_uncovered_pairs fields (peers: {[t['peer'] for t in not_exempt]}).")


if __name__ == "__main__":
    main()
