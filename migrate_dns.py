#!/usr/bin/env python3
"""
Push ASA DNS configuration (parsed by parse_asa_config.py) into FTD via the
FDM REST API: one DNSServerGroup object per `dns server-group NAME` block,
assigned to the data interfaces so it's actually used for lookups
(mirroring ASA's `dns domain-lookup <interface>` lines).

CONFIRMED end-to-end against a live FTD 7.6.4 box -- pushed live and
verified by reading both objects back. Real corrections from this script's
first, guessed version:
- `dnsServers` is a list of **objects** `{"ipAddress": "x.x.x.x", "type":
  "dnsserver"}`, not a list of plain IP strings.
- The data-interface assignment isn't a bare settings singleton at
  `devicesettings/default/dnssettings` (the original guess) -- it's a real
  object type, `datadnssettings`, at `devices/default/datadnssettings`
  (GET the collection -- there's exactly one item -- then PUT it back to
  `devices/default/datadnssettings/{id}` with the fields changed). It also
  carries an explicit `interfaces` list (physicalinterface references) that
  this sets from ASA's `dns domain-lookup <interface>` lines via
  `config.yaml`'s `interface_map` -- confirmed live, both `inside` and
  `outside` came back correctly attached.
- ASA's `domain-name` (e.g. `example.com`) maps to DNSServerGroup's real
  `searchDomain` field -- confirmed live, pushed and read back correctly.
- **`DefaultDNS` is a reserved name.** A live POST creating a group with
  that exact name (ASA's own default server-group name, so this will come
  up on most migrations) was rejected: `422
  dnsServerGroupNameCannotBeDefault`. `RESERVED_GROUP_NAMES` below catches
  this and creates it as `{RESERVED_NAME_PREFIX}<name>` instead, printing a
  note when it does.
- **A DNSServerGroup referenced by DataDNSSettings can't be renamed
  in-place.** Confirmed live: `422 dnsServerGroupCannotBeRenamed` --
  "you must remove it from that setting" first. If you ever need to rename
  one by hand: PUT DataDNSSettings to point at a different group
  (temporarily), rename the now-unreferenced group, then PUT
  DataDNSSettings again pointing back at it -- using a **fresh GET**
  for that last PUT, since the first PUT changes the object's `version`
  and a stale one gets rejected with `422 mismatchedVersion`.

`retries`/`timeout` default to 2/2, matching both ASA's own defaults and
what a real FTD-created DNSServerGroup already had.

Usage:
    python migrate_dns.py --config config.yaml --in-dir parsed/
"""
import argparse
import json
import os

from common.fdm_client import load_config, build_client, FdmApiError

DNS_GROUPS_PATH = "object/dnsservergroups"
DATA_DNS_SETTINGS_PATH = "devices/default/datadnssettings"
INTERFACES_PATH = "devices/default/interfaces"


def find_interface_ref(client, iface_path, logical_name):
    interfaces = client.get_all_pages(iface_path)
    for iface in interfaces:
        if iface.get("name") == logical_name or iface.get("hardwareName") == logical_name:
            return {"id": iface["id"], "type": iface.get("type", "physicalinterface")}
    return None


RESERVED_GROUP_NAMES = {"defaultdns"}  # confirmed live: FTD rejects creating a group named this
RESERVED_NAME_PREFIX = "MIGRATED_"  # prefix used when an ASA group name collides with one above


def push_dns_server_groups(client, server_groups, skip_existing):
    path = client.resolve_endpoint(DNS_GROUPS_PATH, ["dns", "servergroup"])
    name_to_ref = {}
    for name, grp in server_groups.items():
        if not grp["name_servers"]:
            print(f"  ! skipping DNS server-group '{name}': no name-server entries parsed")
            continue
        create_name = name
        if name.lower() in RESERVED_GROUP_NAMES:
            create_name = f"{RESERVED_NAME_PREFIX}{name}"
            print(f"  i ASA server-group '{name}' collides with a reserved FTD name -- "
                  f"creating it as '{create_name}' instead")
        body = {
            "name": create_name,
            "dnsServers": [{"ipAddress": ip, "type": "dnsserver"} for ip in grp["name_servers"]],
            "timeout": 2,
            "retries": 2,
            "searchDomain": grp.get("domain_name"),
            "type": "dnsservergroup",
        }
        try:
            created = client.create_or_reuse(path, body, skip_existing)
            name_to_ref[name] = {"id": created["id"], "type": "dnsservergroup"}
        except FdmApiError as e:
            print(f"  ! failed to create DNS server-group '{name}': {e}")
    return name_to_ref


def resolve_dns_interfaces(client, iface_path, interface_map, asa_interfaces):
    refs = []
    for asa_name in asa_interfaces:
        ftd_name = interface_map.get(asa_name)
        if not ftd_name:
            print(f"  ! no interface_map entry for ASA interface '{asa_name}' -- "
                  f"skipping it for DNS assignment")
            continue
        if client.dry_run:
            refs.append({"id": f"dryrun-iface-{ftd_name}", "type": "physicalinterface"})
            continue
        ref = find_interface_ref(client, iface_path, ftd_name)
        if not ref:
            print(f"  ! could not find FTD interface '{ftd_name}' (mapped from ASA "
                  f"'{asa_name}') -- skipping it for DNS assignment")
            continue
        refs.append(ref)
    return refs


def assign_data_interface_dns(client, group_ref, interface_refs):
    """GET-then-PUT the device's single DataDNSSettings object."""
    if client.dry_run:
        existing = {"id": "dryrun-datadnssettings", "type": "datadnssettings",
                    "name": "DataDNSSettings"}
    else:
        try:
            items = client.get_all_pages(DATA_DNS_SETTINGS_PATH)
        except FdmApiError as e:
            print(f"  ! could not read current DNS settings ({e}) -- skipping "
                  f"data-interface DNS assignment, set it by hand in FDM (Device > DNS Server)")
            return
        if not items:
            print("  ! no DataDNSSettings object found -- skipping data-interface "
                  "DNS assignment")
            return
        existing = items[0]
    body = dict(existing)
    body.pop("links", None)
    body["dnsServerGroup"] = group_ref
    if interface_refs:
        body["interfaces"] = interface_refs
    try:
        client.put(f"{DATA_DNS_SETTINGS_PATH}/{existing['id']}", body)
        print(f"  + assigned DNS server-group to data interfaces via "
              f"{DATA_DNS_SETTINGS_PATH}/{existing['id']}")
    except FdmApiError as e:
        print(f"  ! could not update DataDNSSettings ({e}) -- set it by hand in "
              f"FDM (Device > DNS Server) instead")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--in-dir", default="parsed")
    args = ap.parse_args()

    cfg = load_config(args.config)
    skip_existing = cfg.get("options", {}).get("skip_existing", True)
    interface_map = cfg.get("interface_map", {})
    client = build_client(cfg)

    with open(os.path.join(args.in_dir, "dns.json")) as f:
        dns_data = json.load(f)

    print(f"Creating {len(dns_data['server_groups'])} DNS server-group(s)...")
    name_to_ref = push_dns_server_groups(client, dns_data["server_groups"], skip_existing)

    if dns_data.get("domain_lookup_interfaces") and name_to_ref:
        # ASA enables lookup per-interface; FTD's DataDNSSettings has one
        # dnsServerGroup for all of them, so apply the first successfully
        # created group and set its interfaces list from ASA's.
        first_name, first_ref = next(iter(name_to_ref.items()))
        iface_path = client.resolve_endpoint(INTERFACES_PATH, ["interfaces"])
        interface_refs = resolve_dns_interfaces(
            client, iface_path, interface_map, dns_data["domain_lookup_interfaces"])
        print(f"ASA enabled DNS lookup on: {dns_data['domain_lookup_interfaces']} -- "
              f"applying DNS server-group '{first_name}' to those FTD interfaces")
        assign_data_interface_dns(client, first_ref, interface_refs)
    elif dns_data.get("domain_lookup_interfaces"):
        print("  ! ASA had dns domain-lookup enabled but no DNS server-group was "
              "created -- nothing to assign")

    if not cfg.get("options", {}).get("dry_run", True):
        deploy = input("Deploy these changes to the device now? [y/N] ").strip().lower()
        if deploy == "y":
            client.deploy()
        else:
            print("Skipped deploy -- DNS config is staged as pending changes in FDM.")


if __name__ == "__main__":
    main()
