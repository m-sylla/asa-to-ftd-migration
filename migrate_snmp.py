#!/usr/bin/env python3
"""
Push ASA SNMP host/community configuration (parsed by parse_asa_config.py)
into FTD via the FDM REST API.

CONFIRMED end-to-end against a live FTD 7.6.4 box -- both the device-wide
settings PUT and both real ASA SNMP hosts (one v1, one v2c) were pushed
live and succeeded with zero failures:

- The device-wide singleton is `SNMPServerSettings` at
  `devicesettings/default/snmpservers/{id}` (GET-then-PUT, same pattern as
  DataDNSSettings in migrate_dns.py), with real fields `enabled`,
  `location`, `contact`, `community` (a device-wide default community),
  `listenPort`. A live PUT setting `enabled: true` succeeded. This script
  also carries ASA's `location`/`contact`/global `snmp-server community
  <string>` (no host) into it when present.
- Per-host, `snmphost` is a **flat global object collection** at
  `object/snmphosts` (like `object/networks`/`object/dnsservergroups`) --
  NOT nested under the SNMPServerSettings singleton as first guessed (that
  guess 404'd live; `GET object/snmphosts` revealed the real path).
- `managerAddress` is a **NetworkObject reference** (confirmed by two live
  POSTs) -- created/reused via common/net_helpers.py, the same way routes
  and VPN resolve networks.
- `interface` is a **single physicalinterface reference** (confirmed by two
  live POSTs).
- There is **no `snmpVersion` field** on `snmphost` -- version is carried
  entirely by which concrete subtype backs `securityConfiguration`,
  **both of which are now confirmed correct by live POSTs**:
  `snmpv1securityconfiguration` (for the ASA host with no `version` keyword,
  which defaults to "1") and `snmpv2csecurityconfiguration` (for the host
  with `version 2c`), each with a nested `community` field. The device
  accepted and echoed both back (community masked in the response, as
  expected for a sensitive field).
- **`udpPort` must NOT be sent at all.** A first live POST including it (a
  guessed value) was rejected outright: `422 VAL.snmpUdpPortCannotBePassed`.
  It's server-derived -- every successful POST that omitted it came back
  with `udpPort: 162` chosen automatically, regardless of poll/trap. This
  script no longer sends the field.

The two real hosts created during this verification pass are the actual
migrated objects (`SNMP_10-10-22-171`, `SNMP_10-10-10-8`), not test/throwaway
data -- re-running this script will find and reuse them via the
interface+managerAddress dedup check, not duplicate them.

Community strings live in a separate, gitignored `snmp_secrets.yaml` (never
committed) -- same treatment as VPN pre-shared keys in `vpn_secrets.yaml`.
See `common/secrets_store.py`.

Usage:
    python migrate_snmp.py --config config.yaml --in-dir parsed/
"""
import argparse
import json
import os

from common.fdm_client import load_config, build_client, FdmApiError
from common.net_helpers import get_or_create_network, classify_cidr_or_range, NETWORKS_PATH
from common.secrets_store import load_snmp_secrets

SNMP_SERVER_SETTINGS_PATH = "devicesettings/default/snmpservers"  # confirmed
SNMP_HOSTS_PATH = "object/snmphosts"  # confirmed
INTERFACES_PATH = "devices/default/interfaces"

# GUESS -- unconfirmed subtype name/field, see module docstring
SECURITY_CONFIG_TYPE_MAP = {"1": "snmpv1securityconfiguration",
                             "2c": "snmpv2csecurityconfiguration"}


def _security_configuration(version, community):
    return {"type": SECURITY_CONFIG_TYPE_MAP.get(version, "snmpv2csecurityconfiguration"),
            "community": community}


def find_interface_ref(client, iface_path, logical_name):
    interfaces = client.get_all_pages(iface_path)
    for iface in interfaces:
        if iface.get("name") == logical_name or iface.get("hardwareName") == logical_name:
            return {"id": iface["id"], "type": iface.get("type", "physicalinterface")}
    return None


def push_snmp_server_settings(client, snmp_data, communities):
    """GET-then-PUT the device-wide SNMPServerSettings singleton."""
    global_key = snmp_data.get("global_community_key")
    if not (snmp_data.get("hosts") or snmp_data.get("location")
            or snmp_data.get("contact") or global_key):
        return
    if client.dry_run:
        existing = {"id": "dryrun-snmpserver", "type": "snmpserver", "name": "SNMPServerSettings"}
    else:
        try:
            items = client.get_all_pages(SNMP_SERVER_SETTINGS_PATH)
        except FdmApiError as e:
            print(f"  ! could not read current SNMP server settings ({e}) -- skipping, "
                  f"set enabled/location/contact/community by hand in FDM if needed")
            return
        if not items:
            print("  ! no SNMPServerSettings object found -- skipping")
            return
        existing = items[0]
    body = dict(existing)
    body.pop("links", None)
    body["enabled"] = True
    if snmp_data.get("location"):
        body["location"] = snmp_data["location"]
    if snmp_data.get("contact"):
        body["contact"] = snmp_data["contact"]
    if global_key and communities.get(global_key):
        body["community"] = communities[global_key]
    try:
        client.put(f"{SNMP_SERVER_SETTINGS_PATH}/{existing['id']}", body)
        print(f"  + updated device-wide SNMP settings via "
              f"{SNMP_SERVER_SETTINGS_PATH}/{existing['id']}")
    except FdmApiError as e:
        print(f"  ! could not update SNMPServerSettings ({e}) -- set "
              f"enabled/location/contact/community by hand in FDM")


def _find_existing_host(client, path, interface_id, manager_id):
    if client.dry_run:
        return None
    try:
        existing = client.get_all_pages(path)
    except FdmApiError:
        return None
    for item in existing:
        if (item.get("interface", {}).get("id") == interface_id
                and item.get("managerAddress", {}).get("id") == manager_id):
            return item
    return None


def push_snmp_hosts(client, hosts, communities, interface_map, skip_existing):
    if not hosts:
        return 0
    path = client.resolve_endpoint(SNMP_HOSTS_PATH, ["snmp", "host"])
    iface_path = client.resolve_endpoint(INTERFACES_PATH, ["interfaces"])
    net_path = client.resolve_endpoint(NETWORKS_PATH, ["network"])
    created_count = 0
    for host in hosts:
        key = host["community_key"]
        community = communities.get(key)
        if not community:
            print(f"  ! no community found for host {host['ip']} (key '{key}') in "
                  f"snmp_secrets.yaml -- add it there and re-run. Skipping for now.")
            continue
        ftd_iface_name = interface_map.get(host["interface"])
        if not ftd_iface_name:
            print(f"  ! no interface_map entry for ASA nameif '{host['interface']}', "
                  f"skipping SNMP host {host['ip']}")
            continue
        if client.dry_run:
            iface_ref = {"id": f"dryrun-iface-{ftd_iface_name}", "type": "physicalinterface"}
            manager_ref = {"id": f"dryrun-host-{host['ip']}", "type": "networkobject"}
        else:
            iface_ref = find_interface_ref(client, iface_path, ftd_iface_name)
            if not iface_ref:
                print(f"  ! FTD interface '{ftd_iface_name}' not found on device, "
                      f"skipping SNMP host {host['ip']}")
                continue
            sub_type, value = classify_cidr_or_range(f"{host['ip']}/32")
            manager_ref = get_or_create_network(client, net_path, value, sub_type, skip_existing)
        if skip_existing:
            existing = _find_existing_host(client, path, iface_ref["id"], manager_ref["id"])
            if existing:
                print(f"  = SNMP host {host['ip']} on {host['interface']} already exists "
                      f"(id={existing.get('id')}), reusing")
                created_count += 1
                continue
        body = {
            "name": f"SNMP_{host['ip'].replace('.', '-')}",
            "managerAddress": manager_ref,
            "interface": iface_ref,
            "pollEnabled": "poll" in host["traffic"],
            "trapEnabled": "trap" in host["traffic"],
            "securityConfiguration": _security_configuration(host["version"], community),
            "type": "snmphost",
        }
        client.validate_body_fields(path, body)
        try:
            created = client.post(path, body)
            print(f"  + created SNMP host {host['ip']} on {host['interface']} "
                  f"(id={created.get('id')})")
            created_count += 1
        except FdmApiError as e:
            print(f"  ! failed to create SNMP host {host['ip']} on {host['interface']}: {e}")
    return created_count


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--in-dir", default="parsed")
    ap.add_argument("--secrets-file", default="snmp_secrets.yaml")
    args = ap.parse_args()

    cfg = load_config(args.config)
    skip_existing = cfg.get("options", {}).get("skip_existing", True)
    interface_map = cfg.get("interface_map", {})
    client = build_client(cfg)

    with open(os.path.join(args.in_dir, "snmp.json")) as f:
        snmp_data = json.load(f)
    communities = load_snmp_secrets(args.secrets_file)

    print("Updating device-wide SNMP settings (enabled/location/contact/community)...")
    push_snmp_server_settings(client, snmp_data, communities)

    print(f"Creating {len(snmp_data['hosts'])} SNMP host(s)...")
    created_count = push_snmp_hosts(
        client, snmp_data["hosts"], communities, interface_map, skip_existing)
    print(f"Processed {len(snmp_data['hosts'])} SNMP host definition(s), "
          f"created/reused {created_count}.")

    if not cfg.get("options", {}).get("dry_run", True):
        deploy = input("Deploy these changes to the device now? [y/N] ").strip().lower()
        if deploy == "y":
            client.deploy()
        else:
            print("Skipped deploy -- SNMP config is staged as pending changes in FDM.")


if __name__ == "__main__":
    main()
