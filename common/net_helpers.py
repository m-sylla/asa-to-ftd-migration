import re

NETWORKS_PATH = "object/networks"

_TAG_BY_SUBTYPE = {"HOST": "HOST", "RANGE": "RANGE"}


def classify_cidr_or_range(value):
    """Turn one of the parser's network-reference strings into (sub_type, value)
    for get_or_create_network(). Handles the three shapes _object_to_cidr() /
    resolve_group_networks() produce: 'ip/32' (host), 'ip/prefix' (network),
    and 'start-end' (an ASA `range` object, which has no '/'  -- FDM has a
    dedicated RANGE subType for this, it isn't a NETWORK with a weird mask)."""
    if value.endswith("/32"):
        return "HOST", value[:-3]
    if "/" in value:
        return "NETWORK", value
    if "-" in value:
        return "RANGE", value
    return "HOST", value  # bare IP with neither -- treat as a host


def _find_by_value(client, net_path, sub_type, value):
    """Look up an existing NetworkObject with this exact subType/value,
    regardless of its name, so a value that already has a real ASA-named
    object (created by migrate_network_objects.py) gets reused instead of a
    second, auto-named duplicate -- find_by_name() only matches by name, and
    the generated NET_<value>/HOST_<value> name never matches a hand-picked
    ASA object name for the same value. Caches the full object/networks
    listing on the client (one GET per script run, not per lookup)."""
    if client.dry_run:
        return None
    cache = getattr(client, "_network_value_cache", None)
    if cache is None:
        cache = {}
        for obj in client.get_all_pages(net_path):
            key = (obj.get("subType"), obj.get("value"))
            cache.setdefault(key, obj)
        client._network_value_cache = cache
    return cache.get((sub_type, value))


def get_or_create_network(client, net_path, value, sub_type, skip_existing):
    """Reuse a NetworkObject matching `value` if one exists -- by value first
    (see _find_by_value()), then by the deterministic generated name below,
    or FTD's built-in "any-ipv4" for 0.0.0.0/0 -- otherwise create it. Shared
    by migrate_routes.py, migrate_s2s_vpn.py and migrate_access_control.py so
    the same value referenced from more than one place maps to one object
    instead of duplicates."""
    if sub_type == "NETWORK" and value == "0.0.0.0/0":
        existing = client.find_by_name(net_path, "any-ipv4")
        if existing:
            return {"id": existing["id"], "type": "networkobject"}
    existing = _find_by_value(client, net_path, sub_type, value)
    if existing:
        return {"id": existing["id"], "type": "networkobject"}
    tag = _TAG_BY_SUBTYPE.get(sub_type, "NET")
    safe = re.sub(r"[./]", "-", value)
    name = f"{tag}_{safe}"[:64]
    body = {"name": name, "description": "auto-created during ASA migration",
            "subType": sub_type, "value": value, "type": "networkobject"}
    created = client.create_or_reuse(net_path, body, skip_existing)
    cache = getattr(client, "_network_value_cache", None)
    if cache is not None:
        cache[(sub_type, value)] = created
    return {"id": created["id"], "type": "networkobject"}
