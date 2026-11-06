# ASA 9.12 -> FTD 7.6.4 (local FDM) migration scripts

Migrates network objects, static routes, policy-based site-to-site VPN
(including the NAT exemption that keeps that VPN traffic untranslated),
general NAT/PAT translation rules, the Access Control rules that let VPN
traffic actually pass, DNS, SNMP, NTP, ICMP control-plane access, and
HTTPS management access, from an ASA `show running-config` dump into a
locally-managed FTD via the FDM REST API. ASA's logging `from-address`/
`ftp-server` are parsed and reported, not pushed -- see "Logging" below.

Network objects, routes, site-to-site VPN, Access Control, SNMP, DNS, and
NTP have all been run live against a real FTD 7.6.x box on a real (large:
~500 objects, ~100 groups, ~80 routes, ~40 tunnels, ~135 manual NAT rules)
production ASA config, iterated until every real failure was resolved --
see "Before you run this against a real device", "SNMP", "DNS", and "NTP"
for the specific corrections that came out of that. `migrate_nat.py`
(general NAT/PAT), `migrate_icmp.py`, and `migrate_http_access.py` are the
scripts left that have only been tested in dry-run, never POSTed live --
see "General NAT/PAT", "ICMP control-plane access", and "HTTPS management
access" below before trusting any of them.

For a quick step-by-step checklist of what to run and in what order, see
`RUNBOOK.md`. This file covers the "why" behind each step in more depth.

## Layout

- `common/fdm_client.py` -- auth, generic REST calls, live-spec endpoint
  resolution, deploy.
- `common/net_helpers.py` -- shared "find or create a NetworkObject for this
  CIDR" logic used by both the routes and VPN scripts.
- `common/secrets_store.py` -- reads/writes `vpn_secrets.yaml` (VPN
  pre-shared keys), `snmp_secrets.yaml` (SNMP community strings), and
  `logging_secrets.yaml` (the logging FTP password) -- see "Secrets" below.
- `parser/asa_parser.py` + `parse_asa_config.py` -- turns the ASA config text
  into `network_objects.json`, `routes.json`, `vpn.json`, `nat_exemptions.json`
  (manual/twice NAT rules, both identity and translating), `auto_nat.json`
  (object NAT), `dns.json`, `snmp.json`, `ntp.json`, `logging.json`,
  `icmp_control.json`, `http_management.json`.
- `migrate_network_objects.py`, `migrate_routes.py`, `migrate_s2s_vpn.py`,
  `migrate_access_control.py`, `migrate_nat.py`, `migrate_dns.py`,
  `migrate_snmp.py`, `migrate_ntp.py`, `migrate_icmp.py`,
  `migrate_http_access.py` -- push each piece to FTD, in that order
  (routes/VPN/ACP/NAT all reference objects; ACP rules also need the VPN
  tunnels' local/remote networks; DNS/SNMP/NTP/ICMP/HTTPS-access are
  independent of everything else and can run any time). `migrate_logging.py`
  reports ASA's logging `from-address`/`ftp-server` rather than pushing them
  -- see "Logging" below.
- `sample/sample_asa.cfg` -- a small config you can run the parser against to
  see the expected JSON shape.
- `RUNBOOK.md` -- a step-by-step checklist for running everything in order.
- `normalize_asa_config.py` -- standalone ASA config cleanup tool, unrelated
  to the FTD migration pipeline. See "ASA config normalizer" below.
- `find_unused_objects.py` -- standalone report of `object network`/
  `object-group network` definitions never referenced anywhere else in the
  config, unrelated to the FTD migration pipeline. See "Unused objects
  report" below.
- `backup_automation/` -- standalone FDM backup automation (`backup_to_ftp.py`
  + its example secrets file), unrelated to the migration pipeline (FDM
  itself has no remote-backup scheduling at all -- see "Backup automation"
  below). **Not confirmed against a live device yet.**

## Setup

```
py -m pip install -r requirements.txt
copy config.example.yaml config.yaml
```

Edit `config.yaml`:
- `ftd.host` / `username` / `password` -- an FDM local admin account.
- `interface_map` -- ASA `nameif` -> FTD logical interface name. Get FTD
  names from Device > Interfaces in FDM. This can't be inferred, ASA and FTD
  interface naming are independent even on the same hardware.
- `options.dry_run: true` (default) -- prints every request instead of
  sending it. Keep this on until you've reviewed the output.

## Usage

```
# 1. Export the config
#    On the ASA: `show running-config` > save output to asa-config.txt

# 2. Parse it
py parse_asa_config.py asa-config.txt --out-dir parsed/
#    Review parsed/*.json, especially parsed/unparsed_lines.json and any
#    "UNRESOLVED"/"OBJECT:" markers or nat_exempt: false entries in vpn.json.

# 3. Push objects first (routes and VPN reference these)
py migrate_network_objects.py --config config.yaml --in-dir parsed/

# 4. Push routes
py migrate_routes.py --config config.yaml --in-dir parsed/

# 5. Push site-to-site VPN (NAT exemption is included automatically)
py migrate_s2s_vpn.py --config config.yaml --in-dir parsed/

# 6. Push Access Control rules permitting that VPN traffic
py migrate_access_control.py --config config.yaml --in-dir parsed/
#    IMPORTANT: check rule order in FDM before deploying -- a new rule
#    appended after an existing catch-all deny will never be evaluated.
#    See "Access Control for VPN traffic" below.

# 7. Push general NAT/PAT translation rules
py migrate_nat.py --config config.yaml --in-dir parsed/
#    UNVERIFIED against a live device -- run with dry_run: true and read
#    "General NAT/PAT" below before trusting a live run.

# 8. Push DNS server-group(s) + data-interface DNS assignment
py migrate_dns.py --config config.yaml --in-dir parsed/
#    Confirmed live -- see "DNS" below.

# 9. Push SNMP hosts (community strings come from snmp_secrets.yaml)
py migrate_snmp.py --config config.yaml --in-dir parsed/
#    Confirmed live -- see "SNMP" below.

# 10. Push NTP servers
py migrate_ntp.py --config config.yaml --in-dir parsed/
#    Schema confirmed against a real live GET, but not yet POSTed --
#    see "NTP" below.

# 11. Push ICMP control-plane access (which hosts may ping the device itself)
py migrate_icmp.py --config config.yaml --in-dir parsed/
#    UNVERIFIED against a live device -- see "ICMP control-plane access" below.

# 12. Push HTTPS management access (which hosts may reach FDM's own web UI)
py migrate_http_access.py --config config.yaml --in-dir parsed/
#    UNVERIFIED against a live device -- see "HTTPS management access" below.

# 13. Report logging from-address/ftp-server (no live equivalent confirmed)
py migrate_logging.py --in-dir parsed/
#    Report only, nothing pushed -- see "Logging" below.
```

Each script asks whether to deploy (push pending changes live) once it's
done, or you can leave changes staged and deploy manually from FDM.

## ASA config normalizer (standalone, optional)

`normalize_asa_config.py` is unrelated to the FTD migration pipeline above
-- it doesn't produce JSON and none of the `migrate_*.py` scripts read its
output. It's a separate tool that reads an ASA config and writes out a
cleaned-up copy of the config *text itself*:

```
py normalize_asa_config.py asa-config.txt --out parsed/asa-config-normalized.txt
```

It does two things:
1. Resolves `name <ip> <alias>` substitutions wherever an alias is used as
   a route's gateway or as a raw address inside an `object-group network`
   member (`network-object host <alias>` / `network-object <alias> <mask>`),
   replacing the alias text with its literal IP. Nothing else in the file is
   touched -- an alias used elsewhere (ACLs, crypto peer statements, an
   `object network`'s own `host` line, etc.) is deliberately out of scope.
2. For every `object-group network` member that's a raw literal address
   rather than a `network-object object <name>` reference, it either
   rewrites the member to reference a pre-existing `object network` of the
   same value, or creates a new one (inserted just before the first
   `object-group network` block) and rewrites the member to reference that
   instead. Generated names follow the same `HOST_<ip>`/`NET_<net>-<prefix>`
   convention used elsewhere in this toolkit (`common/net_helpers.py`).

Verified against a real ~1300-line slice of a production config (routes +
object network/object-group network sections, a newer export than
`asa-config.txt` elsewhere in this repo -- specific names/IPs below are
genericized, not the real values): 34 alias substitutions and 24
object-group literal members handled (15 matched to a pre-existing object
network of the same value under a *different* name -- e.g. an alias
resolving to `192.168.50.0/24` correctly found and reused the pre-existing
`REMOTE-NET` object instead of creating a redundant one -- and 9 had no
match and got a new object network created). This run caught and fixed a
real gap: aliases can appear in a route's **destination network**, not just
its gateway (`route outside RemoteVendor 255.255.255.128
203.0.113.254 1`) -- the first version of this script only checked the
gateway position. Also verified against the full real ~2000-line
`asa-config.txt` (0 aliases used in routes/groups there, 0 raw group
literals -- confirms it's a safe no-op on an already-clean config) and the
sample config's one raw `network-object host` literal (correctly promoted
to a new object).

## Unused objects report (standalone, optional)

`find_unused_objects.py` is unrelated to the FTD migration pipeline --
nothing else reads its output. It reports every `object network` /
`object-group network` definition never referenced anywhere else in the
config, as a cleanup candidate list:

```
py find_unused_objects.py asa-config.txt --out parsed/unused_objects.json
```

It reads the raw ASA config text, not `parsed/network_objects.json` --
this project's parser resolves object/group references down to literal
IPs/CIDRs for the migration scripts, so that JSON has already lost the
name-level reference information needed to answer "is this object
referenced anywhere." For every object/group definition, it searches the
rest of the config (excluding that definition's own header + body lines,
including a second `object network NAME` header ASA sometimes re-prints
just to attach a NAT association) for the name as a whole word. Any match
elsewhere -- `network-object object NAME` / `group-object NAME` in another
group, `object NAME` / `object-group NAME` in an access-list, `nat (...)
... static NAME NAME` -- counts as a real reference, without needing to
special-case each ASA command.

This is a whole-word text search, not a full reference-graph walk, so it
errs toward under-reporting (a coincidental text match reads as "used")
rather than over-reporting -- the safer direction for a cleanup-candidate
list. **Review before deleting anything**; this is a starting point for
manual review, not an authoritative "safe to delete" list.

Verified against the real ~2000-line `asa-config.txt`: 98/477 network
objects and 36/101 object-groups appear unused. Spot-checked several by
hand against the raw config text: a clearly-throwaway test object (`host
1.1.1.1`) was correctly flagged; heavily-referenced objects (e.g. the
device's `any`-equivalent object, an object used in dozens of routes) were
correctly *not* flagged; and several `NATVers*`-named object-groups whose
names strongly suggest they were built for a manual NAT rule turned out to
have no reference anywhere in the config at all outside their own
definition -- a real, plausible finding (leftover groups from a NAT rule
that was later removed or changed), not a tool bug, confirmed by grepping
the raw config directly.

## Backup automation (standalone, optional)

`backup_automation/` is unrelated to the migration pipeline -- it exists
because FDM has no native remote-backup capability at all: backups are
local-only, stored on the box under `/ngfw/var/sf/backup/`, non-durable
(purged under disk pressure, wiped entirely on any non-hotfix upgrade), and
there's no SCP/FTP scheduling option in FDM's UI or API, unlike FMC which
does support a configured remote-storage device. `backup_to_ftp.py` in that
folder triggers an on-demand backup via the FDM REST API, downloads it, and
FTPs (or FTPS, if `tls: true`) it off-box -- meant to be run on a schedule
from a jump host/management server the customer controls (cron, Scheduled
Task, etc.), since FDM itself can't run arbitrary scripts.

Unlike everything else in this repo, `backup_automation/` is **fully
self-contained on purpose** -- its own `requirements.txt`, its own
`config.example.yaml`/`backup_secrets.example.yaml`, its own copy of
`common/fdm_client.py`, and its own `README.md` -- so the whole folder can be
handed to the customer by itself, without the rest of this migration
toolkit. See `backup_automation/README.md` for the customer-facing
prerequisites and setup steps; it's written to stand alone, not assuming the
reader has seen this README. Because `fdm_client.py` is duplicated rather
than shared, a fix made to the copy at the project root (`common/`) won't
automatically reach the one in `backup_automation/common/` -- copy it over by
hand if that ever matters.

**UNCONFIRMED against a live device -- every endpoint/field name comes from
Cisco's own FDM REST API reference and a Cisco Community writeup, not a live
test against this project's FTD.** Read the script's own docstring before
trusting a scheduled run against the real box -- it lists exactly which
pieces (the `scheduleType` value, the backup job-status path, the archived-
backups listing, the download call) are documented-but-unverified and what to
check in `/#/api-explorer` if any of them fails. Also worth a decision before
relying on this for anything real: plain FTP sends the backup unencrypted
over the network -- set `backup.ftp.tls: true` for FTPS, and/or set
`encryption_key` in `backup_secrets.yaml` to encrypt the backup file itself.

## What the parser handles

- `object network` (host/subnet/range/fqdn) and `object-group network`
  (including nested `group-object` and inline `network-object host|<net>
  <mask>` literals).
- `route <if> <net> <mask> <gw> [metric]`, including the default route.
- Policy-based (crypto-map) site-to-site VPN: `crypto map ... match address /
  set peer / set ikev1 transform-set / set ikev2 ipsec-proposal / set pfs /
  set security-association lifetime`, `crypto ikev1|ikev2 policy`, `crypto
  ipsec ikev1 transform-set` / `ikev2 ipsec-proposal`, `tunnel-group ...
  ipsec-attributes` (pre-shared-key only), and the ACL referenced by `match
  address` (resolving `object`/`object-group`/`host`/bare `net mask`/`any`).
- Manual/twice NAT: `nat (if1,if2) source static|dynamic X Y [destination
  static|dynamic A B] [no-proxy-arp] [route-lookup]`. Every such rule is
  parsed into `nat_exemptions.json`'s `rules` list (despite the file name,
  it now holds every manual NAT rule, not just identity ones) with an
  `is_identity` flag. Identity rules (`source static X X` -- same object on
  both sides) are ASA's idiom for exempting VPN traffic from translation:
  each tunnel in `vpn.json` gets a `nat_exempt` boolean, which rule(s) proved
  it (`matched_nat_exemption_rules`), which interface that's scoped to on FTD
  (`nat_exempt_interface`), and exactly which (local, remote) pairs aren't
  covered (`nat_exempt_uncovered_pairs`) if incomplete. Non-identity rules
  (genuine translations) are migrated separately by `migrate_nat.py`.
- Auto-NAT (object NAT): `object network NAME` / `nat (real,mapped)
  static|dynamic <target>`, where `<target>` is an object name, a literal
  IP, or the word `interface` (PAT using the egress interface's own
  address). Written to `auto_nat.json`.
- DNS: `dns domain-lookup <if>` (which interfaces have lookups enabled) and
  `dns server-group NAME` blocks (`name-server`/`domain-name`). Written to
  `dns.json`.
- SNMP: `snmp-server host <if> <ip> [poll|trap] community <string> [version
  <ver>]`, `snmp-server community <string>`, `snmp-server location/contact`.
  Community strings are pulled out to `snmp_secrets.yaml` (see "Secrets"),
  everything else to `snmp.json`. `no snmp-server ...` negation lines are
  treated as not-configured, not an error.
- NTP: `ntp server <ip-or-hostname> [source <if>] [prefer]`. Written to
  `ntp.json`. Other `ntp ...` subcommands (`ntp authenticate`, `ntp
  trusted-key`, `ntp authentication-key`) aren't handled -- FTD's confirmed
  NTP schema has nothing to map them to either -- and are recorded as
  unparsed.
- `name <ip> <alias>` aliases: parsed into a simple `{alias: ip}` map
  (`parse_name_aliases()`) used to resolve an alias wherever one shows up in
  place of a literal IP -- ASA allows this virtually anywhere an address is
  expected. Used by the ICMP and HTTPS management access parsers below (and
  by `normalize_asa_config.py`, which imports the same function).
- Logging: `logging from-address <email>` and `logging ftp-server <host>
  <path> <username> <password>` only. Written to `logging.json`; the
  password goes to `logging_secrets.yaml` (see "Secrets"). Everything else
  under `logging` (enable, timestamps, buffer-size, per-message severity
  overrides, syslog servers, etc.) is out of scope.
- ICMP control-plane access: `icmp permit|deny [host <ip> | <net> <mask> |
  any] <interface>` -- which hosts/networks may send ICMP to the firewall's
  own interfaces (unrelated to through-traffic ACLs). Written in file order
  to `icmp_control.json`, since evaluation is top-to-bottom, first match
  wins. `icmp unreachable rate-limit ...` (a separate global setting) is
  out of scope.
- HTTPS management access: `http server enable` and `http <net-or-alias>
  <mask> <interface>` -- which networks may reach ASDM/the device's own
  management interface. Written to `http_management.json`.

**Not handled** (will show up in `unparsed_lines.json` or simply be absent):
IPv6, route-based/VTI VPN, certificate-based IKE auth, dynamic crypto maps,
PAT pools (a dynamic NAT mapped to an object-group of addresses), per-
service/port NAT translation, ACLs/access-groups (interface ACLs), object
types other than `network` (e.g. `object service`), SNMPv3 (user-based)
hosts, SNMP trap-category selection (`snmp-server enable traps ...`), NTP
authentication (`ntp authenticate`/`trusted-key`/`authentication-key`), the
global ACL (`access-list ... global` / `access-group ... global`), and most
of `logging` (see above).

## NAT exemption

Confirmed against a live device (not guessed): FTD doesn't need a separate
NAT rule object for VPN exemption. It's one field on the site-to-site
connection profile itself, `interfaceForNatExempt` -- `null` when disabled,
or a reference to the *internal* (real-side) interface when enabled, scoped
automatically by that same profile's `localNetworks`/`remoteNetworks`. This
mirrors the ASA's own model, where the NAT-exemption rule's real interface
is the internal one and the same local/remote objects already define the
crypto ACL.

`migrate_s2s_vpn.py` sets this field automatically from what the parser
found on the ASA -- no separate script or NAT rule object needed. If a
tunnel's ASA config had no matching identity NAT rule, `interfaceForNatExempt`
is left `null` (matching ASA's behavior: that traffic would have been
translated there too) and the script prints a warning so you can confirm
that's actually what you want.

## Access Control for VPN traffic

**This is a real gotcha, not an edge case**: ASA's `sysopt connection
permit-vpn` is enabled by default, so decrypted VPN traffic bypasses the
interface ACL entirely. FTD's Access Control Policy does **not** exempt
decrypted VPN traffic by default -- a tunnel can be fully up (Phase 1/2
established) while zero traffic passes, because nothing in the ACP permits
it. `migrate_access_control.py` creates two Access Control rules per tunnel
(one per direction) to cover this.

Check your ASA with `show running-config all sysopt | include permit-vpn` --
if it shows the bypass is active (the common default), you almost certainly
need this step on FTD even though nothing equivalent existed explicitly on
the ASA side.

Endpoint and field names are confirmed against a live FTD AccessRule (not
guessed): `policy/accesspolicies/{id}/accessrules`, type `accessrule`, and
critically the action field is **`ruleAction`**, not `action`. Per tunnel,
two unidirectional rules are created -- `VPN_<peer>_OUT` (source zone =
internal/NAT-exempt interface's zone, destination zone = the VPN-terminating
interface's zone, source networks = local, destination networks = remote)
and `VPN_<peer>_IN` (the reverse) -- matching the single-zone-each-side,
single-direction shape of a real confirmed rule, rather than combining both
directions into one rule. FTD's ACP is stateful so either rule's own return
traffic is already covered, but either side of a site-to-site tunnel can
initiate a new connection, hence two rules. This was confirmed to resolve
zones correctly against a simple one-zone-per-interface layout (an
`inside_zone` containing the `inside` interface, `outside_zone` containing
`outside`).

Two things this deliberately does NOT attempt, because guessing them wrong
would be worse than not touching them:
- **Rule order.** New rules may be appended after an existing rule in the
  policy; if that existing rule is a broad/catch-all deny, the new VPN rules
  will never be evaluated. The script prints what the current last rule in
  the policy is before creating anything -- read that output, and manually
  reorder the new rules above any catch-all deny in FDM before deploying.
- **Protocol/port granularity.** If your ASA's crypto-map ACL restricted
  specific protocols/ports rather than a blanket `permit ip`, that's not
  carried over -- every rule here permits all traffic between the local and
  remote networks. Narrow it by hand in FDM if that matters for your setup.

## General NAT/PAT

`migrate_nat.py` migrates everything NAT-related that isn't the VPN
exemption slice above: non-identity manual NAT rules (genuine translations)
and auto-NAT (object NAT) rules -- ASA's usual mix of general internet-bound
dynamic PAT and static 1:1 translations for published servers.

**This is the least-tested script in the toolkit.** Unlike everything else
here, it has only run in `dry_run: true` mode (successfully, against ~65
real rules from a real ASA config with no crashes) -- it has never actually
POSTed to a live device. `MANUAL_NAT_PATH` (`devices/default/manualnats`),
`AUTO_NAT_PATH` (`devices/default/objectnats`), and every field in both
bodies (`natType`, `originalSource`/`translatedSource`,
`originalNetwork`/`translatedNetwork`, `interfaceIpv4` for PAT-via-interface,
etc.) are best-effort guesses, not confirmed data -- the one earlier attempt
at a NAT-rule endpoint in this project was abandoned before being tested,
because VPN NAT exemption turned out not to need a separate rule object at
all (see above). If you can share a GET of one existing manual NAT rule and
one existing auto-NAT rule from `https://<ftd-host>/#/api-explorer`, the
same way routes/VPN/NAT-exemption/ACP were corrected earlier in this
project, this can be corrected for real.

General NAT also carries more blast radius than anything else here -- it can
affect most or all traffic through the device, not just VPN peers -- so:
read every printed dry-run body carefully, and review NAT rule **order** in
FDM afterward (this script doesn't control where new rules land relative to
each other or any existing NAT rules, and NAT evaluation order changes what
actually happens to a packet).

Not attempted at all: PAT pools, per-service/port NAT, and any auto-NAT rule
whose object has no resolvable value (this can happen -- one real example
was a `nat (...)` association on an object with no `host`/`subnet` anywhere
in the config, which looks like an orphaned/incomplete object on the ASA
itself; the script skips these with a clear message rather than guessing).

## DNS

`migrate_dns.py` creates one `DNSServerGroup` object per ASA `dns
server-group NAME` block (typically just `DefaultDNS`) and assigns it to
the data interfaces -- the FTD equivalent of ASA's `dns domain-lookup
<interface>` lines being enabled.

**Run live against the real FTD box and confirmed end-to-end** -- pushed
and read back to verify. Corrections that came out of that:
- `dnsServers` is a list of objects `{"ipAddress": "x.x.x.x", "type":
  "dnsserver"}`, not plain IP strings.
- The data-interface assignment is a real object type, `datadnssettings`,
  at `devices/default/datadnssettings` (GET the one-item collection, PUT it
  back to `.../{id}` with `dnsServerGroup` and `interfaces` changed) -- not
  the originally-guessed `devicesettings/default/dnssettings`. `interfaces`
  (physicalinterface references) is set explicitly from ASA's `dns
  domain-lookup <interface>` lines via `config.yaml`'s `interface_map` --
  confirmed live with both `inside` and `outside` correctly attached.
- ASA's `domain-name` (e.g. `example.com`) maps to DNSServerGroup's real
  `searchDomain` field and is pushed, confirmed by reading it back.
- **`DefaultDNS` is a reserved name on FTD.** A live POST creating a group
  named exactly that (ASA's own default server-group name, so this comes up
  on most migrations) was rejected: `422 dnsServerGroupNameCannotBeDefault`.
  The script now creates it as `XXX_<name>` instead when this collision
  happens (this device's actual group is `XXX_DefaultDNS`), printing a note
  when it does.
- **A DNSServerGroup referenced by DataDNSSettings can't be renamed
  in-place** (`422 dnsServerGroupCannotBeRenamed`) -- confirmed live while
  renaming this device's group from an earlier `ASA_DefaultDNS` to
  `XXX_DefaultDNS`. It has to be detached from DataDNSSettings first,
  renamed, then reattached with a fresh GET (a stale one gets
  `422 mismatchedVersion`). Not something `migrate_dns.py` itself needs to
  do, but worth knowing if you ever rename one by hand.

## SNMP

`migrate_snmp.py` updates the device-wide SNMP singleton (`enabled`,
`location`, `contact`, a global default `community`) and creates one SNMP
host entry per ASA `snmp-server host` line (community-based; SNMPv3
user-based hosts aren't parsed -- see "What the parser handles"). Community
strings live in `snmp_secrets.yaml`, not `parsed/snmp.json` -- see "Secrets"
below.

**Run live against the real FTD box and confirmed end-to-end** -- both real
ASA SNMP hosts (one v1, one v2c) were pushed and created with zero
failures, along with the device-wide settings update. What that live run
corrected from the first, guessed version of this script:
- The device-wide singleton is real: `SNMPServerSettings` at
  `devicesettings/default/snmpservers/{id}` (GET-then-PUT, same pattern as
  DNS's `DataDNSSettings`), with real fields `enabled`/`location`/
  `contact`/`community`/`listenPort`.
- Per-host, `snmphost` is a **flat global object collection** at
  `object/snmphosts` (like `object/networks`) -- not nested under the
  SNMPServerSettings singleton as first guessed (that guess 404'd live).
- `managerAddress` is a **NetworkObject reference** (not a raw IP string as
  first guessed) -- created/reused via `common/net_helpers.py` the same way
  routes and VPN resolve networks.
- `interface` is a **single physicalinterface reference** (not a plain
  interface-name string as first guessed).
- There is **no `snmpVersion` field** on `snmphost` at all. Version is
  carried by which concrete subtype backs `securityConfiguration` --
  `snmpv1securityconfiguration` and `snmpv2csecurityconfiguration`, each
  with a nested `community` field, are now **both confirmed correct** (one
  live POST of each succeeded and was read back).
- **`udpPort` must never be sent** -- a live POST including it was rejected
  (`422 VAL.snmpUdpPortCannotBePassed`); it's server-derived (came back as
  `162` on every successful create, regardless of poll/trap).

The two hosts created during that verification pass are the real migrated
objects, not throwaway test data -- re-running the script finds and reuses
them (matched on interface + `managerAddress`) instead of duplicating them.

## NTP

`migrate_ntp.py` pushes ASA's `ntp server` lines into FTD's NTP settings.

**Run live against the real FTD box and confirmed working.** The real
`ntp` object is flat -- `enabled` + `ntpServers` (a plain list of strings)
-- confirmed correct by a live PUT that was read back afterward
(`enabled: true`, `ntpServers: ["10.1.1.53", "192.168.50.10"]`, preferred
server first -- IPs genericized here, not the real values). ASA's
per-server `source <interface>` has no equivalent
field in this schema; the script drops it and prints a one-line notice per
server rather than silently losing it. ASA's `prefer` keyword has no
equivalent field either -- the parser (`parse_ntp()` in
`parser/asa_parser.py`) approximates it by sorting the preferred server(s)
first in `ntpServers`, which is the closest available approximation, not a
confirmed behavior.

**A real oddity, now resolved by that live run**: `GET
devicesettings/default/ntp` returns **two** NTP settings objects on this
device, both starting out as identical factory defaults --
`00000004-0000-0000-0000-000000000002` (the all-zeros-prefixed synthetic ID
pattern FTD uses for its real built-in singletons, same style as DNS's
`DataDNSSettings` id `00000013-...`) and `954f490f-7e76-11e5-bfa4-bbacca2d71bc`
(an ordinary-looking UUID). A live PUT to the first succeeded; the same PUT
to the second was rejected: `422 invalidUuid` -- "Validation failed due to
an invalid UUID" for an ID the device's own GET had just returned. So the
`00000004-...` object is the real, editable one; the other is a legacy/decoy
entry that can't be written to. `migrate_ntp.py` still attempts every item
in the collection rather than hardcoding that specific id (in case a
different device's decoy has a different id) and treats a per-item failure
as informational, not fatal.

The real object's `description` field defaults to `null`, which FDM's UI
shows as a generic "User-Defined NTP Servers" placeholder. `migrate_ntp.py`
leaves it untouched.

Not attempted: NTP authentication (`ntp authenticate`/`trusted-key`/
`authentication-key`) -- no field for it in the confirmed schema, and ASA's
config for this migration doesn't use it anyway.

## Logging

ASA's `logging from-address` (sender address for email-based logging) and
`logging ftp-server` (periodic FTP archival of the local log buffer) are
parsed into `logging.json` (password separately, into
`logging_secrets.yaml`), but `migrate_logging.py` **only reports them --
it does not push anything.**

**`ftp-server` is confirmed NOT supported on FTD/FDM** -- there is no FTP
log-archival destination in FDM's logging model at all. This is a genuine
feature gap, not a migration this toolkit (or any API call) can bridge --
if the ASA's local log buffer needs archiving somewhere, that requires a
different mechanism entirely (an external syslog server/SIEM), not a
like-for-like replacement.

`from-address` (email-based logging) remains unconfirmed either way --
FTD's logging model is built around local event storage plus external
syslog (or sending events to FMC, for FMC-managed deployments), and it
isn't obvious an "email the log" concept exists on FTD, but this hasn't
been specifically checked the way `ftp-server` was. `migrate_logging.py`
prints what was found (never the password) so you have it for manual
reference, and explains what to check in FDM/API Explorer if you want to
pursue a real equivalent for that piece.

## ICMP control-plane access

`migrate_icmp.py` pushes ASA's `icmp permit`/`icmp deny` entries -- which
hosts/networks may send ICMP to the firewall's own interfaces (not a
through-traffic ACL).

**Unverified -- no real API Explorer data behind this at all**, unlike
this toolkit's other now-confirmed device settings. `ICMP_PATH`
(`devicesettings/default/icmp`) is a guess following the pattern
confirmed for DNS/SNMP/NTP; the body fields (`sourceNetworks`,
`sourceZones`, `action`) are modeled on `migrate_access_control.py`'s
confirmed `accessrule` shape, since every confirmed rule-like object in
this toolkit references security zones, not raw interfaces. Share a real
GET from API Explorer (search "icmp") before trusting a live run.

**Rule order matters and isn't fixed automatically.** ASA evaluates these
top-to-bottom, first match wins. The real config this was built against
has exactly this problem: `icmp deny any inside` appears partway through
the `inside` entries, making two later `icmp permit host ... inside` lines
unreachable already on the ASA. `migrate_icmp.py` detects and prints a
warning for this per interface, and migrates the unreachable entry anyway
(it's your call whether that ASA behavior was intentional or a leftover,
not something to silently drop).

## HTTPS management access

`migrate_http_access.py` pushes ASA's `http server enable` / `http <net>
<mask> <interface>` lines -- which networks may reach ASDM (FDM's web UI,
on FTD).

**Unverified -- same tier of guess as ICMP control-plane access above**,
same reasoning (`HTTP_ACCESS_PATH` guessed as
`devicesettings/default/managementaccess`, zone + network body fields
modeled on the confirmed `accessrule` shape). Any alias in the network
position (confirmed live in the real config: `http TemporaireNVI
255.255.255.255 inside`, where `TemporaireNVI` is a `name` alias) is
resolved to its literal IP by `parse_name_aliases()` before this script
ever sees it.

**Get this one confirmed before trusting a live run more than most.**
Getting it wrong in either direction has real consequences: too permissive
exposes FDM's own web UI beyond what was intended, too restrictive can
lock out legitimate admin access to the device. This is a case where
confirming the real endpoint first is worth more than the usual
dry-run-then-iterate approach.

## Secrets

`parse_asa_config.py` pulls VPN pre-shared keys out of the ASA config in
cleartext (ASA's type 6/8 password encryption is not reversed, and isn't
reversible in the type 8 case) and writes them to their own file,
**`vpn_secrets.yaml`**, at the project root -- not into `parsed/vpn.json`,
so secrets don't ride along with structural VPN data (network refs,
proposals, etc.) that's more likely to get shared, diffed, or pasted
somewhere while troubleshooting. `migrate_s2s_vpn.py` reads both files and
joins them by peer IP when building each tunnel.

`vpn_secrets.yaml` is gitignored by name, exactly like `config.yaml` --
never commit it. `vpn_secrets.example.yaml` is the tracked template showing
the format, for the rare case you need to hand-add a key the parser missed.
**Rotate every migrated key after cutover** regardless -- it passed through
a plaintext ASA config export and this plaintext YAML file along the way,
so treat it as burned once the migration is done.

SNMP community strings get the identical treatment: pulled out of the ASA
config into **`snmp_secrets.yaml`** (keyed by `community_key` -- a host's IP,
or `_global`), separate from `parsed/snmp.json`, gitignored by name, with a
tracked `snmp_secrets.example.yaml` template. `migrate_snmp.py` reads both
files. **Rotate community strings after cutover** for the same reason as
above -- and consider moving to SNMPv3 while you're at it, since community
strings are inherently weak regardless of transport.

The logging FTP password gets the same treatment: pulled into
**`logging_secrets.yaml`**, separate from `parsed/logging.json`, gitignored
by name, with a tracked `logging_secrets.example.yaml` template.
`migrate_logging.py` reads it but only prints *whether* a password was
found, never the value itself.

## Before you run this against a real device

The FDM REST API is documented per-build at `https://<ftd-host>/#/api-explorer`,
and resource/field names have shifted between releases. This toolkit reduces
that risk two ways, but doesn't eliminate it:

1. `FdmClient.resolve_endpoint()` checks the device's own live OpenAPI spec
   (`/apispec/en-us.json`) before using a hardcoded default path, and warns
   if it can't confirm one.
2. `FdmClient.validate_body_fields()` compares each outgoing request's keys
   against that same live spec and warns about anything unrecognized,
   instead of silently sending a field the API will ignore or reject.

Network objects and groups (`object/networks`, `object/networkgroups`) match
real GET output exactly -- no surprises there. Static routes had one real
correction: they are **not** a flat `devices/default/routing/staticrouteentries`
collection as first guessed -- routes are scoped under a virtual router, at
`devices/default/routing/virtualrouters/{vrId}/staticrouteentries`.
`migrate_routes.py` now resolves the right virtual router per interface
(there's normally just one, "Global", on a single-context ASA) before
creating each route.

The site-to-site VPN object model in `migrate_s2s_vpn.py` was corrected
against real API Explorer output from a live FTD box, so the *shape* is
confirmed:
- The connection object is `stosconnectionprofile` at
  `devices/default/s2sconnectionprofiles` (not a generic `object/...` path).
- IKE (Phase 1) policies (`ikev1policies`/`ikev2policies`, types
  `ikevonepolicy`/`ikevtwopolicy`) are **global**, same as ASA's `crypto
  ikev1|ikev2 policy` -- the connection profile has no field referencing
  them at all, so the script creates/enables them once up front rather than
  attaching them per tunnel.
- `ikev1proposals`/`ikev2proposals` (types `ikevoneproposal`/`ikevtwoproposal`)
  are the Phase 2 / IPsec side (ASA's transform-set / ipsec-proposal).
- `remotePeerIpAddress` is a plain string, not an object reference.
- Interfaces are a list field, `outsideInterfaces`.
- `interfaceForNatExempt` handles VPN NAT exemption directly (see above) --
  confirmed by comparing a GET of the same connection profile with it
  disabled (`null`) and enabled (an interface reference).

What's still a best guess: enum values (`encryptionType: "AES256"`,
`encryptionMethod: "ESP_AES_256"`, etc.) for combinations that weren't in
the sample output -- these were extrapolated consistently from the ones
that were confirmed (see `IKE_ENCRYPTION_MAP` / `HASH_MAP` /
`IKEV1_PROPOSAL_ENCRYPTION_MAP` / `IKEV1_PROPOSAL_AUTH_MAP` /
`DH_GROUP_MAP` at the top of `migrate_s2s_vpn.py`). Run with `dry_run: true`
first and read the printed request bodies. If a live POST is rejected,
FDM's validation error names the offending field/value -- fix the relevant
map entry and re-run (existing objects are reused by name via
`skip_existing`, not duplicated).

### What a real live run against a real device actually found

Objects, routes, VPN, and ACP were run live against a real production ASA
config (~500 objects, ~80 routes, ~40 tunnels) and iterated to a clean
state. In case similar issues show up on your device, the real corrections
that came out of that:
- `client.get_apispec()` didn't handle a 200 response with a non-JSON body
  (the web server's SPA shell for an unmatched path) -- crashed instead of
  falling back to defaults. Fixed; now degrades gracefully and prints a
  one-time warning.
- `FdmClient` never stored `self.port`, only used it to build the base URL --
  crashed the first time anything else needed it.
- A duplicate-name rejection from the server didn't fall back to reusing the
  existing object if the pre-check's name lookup missed it (e.g. a case
  difference) -- `create_or_reuse()` now retries with a full unfiltered scan
  before giving up.
- `migrate_routes.py`/`migrate_s2s_vpn.py`/`migrate_access_control.py` all
  had the same gap: object/proposal/zone lookups happening outside any
  try/except, so one bad entry crashed the whole batch instead of being
  skipped. Fixed in all three.
- ASA's `route <if> 0.0.0.0 0.0.0.0 tunneled` (VPN default route, no real
  gateway IP) was being parsed as if `tunneled` were a literal gateway --
  now recognized and skipped cleanly.
- A `/32` destination needs FTD's `HOST` subType with a bare IP, not
  `NETWORK` with a `/32` CIDR (`"Invalid subnet mask"` otherwise).
- ASA `object network` objects with `subType: RANGE` weren't converted to
  FDM's dedicated `RANGE` subType at all, so a range like
  `10.1.1.1-10.1.1.10` was sent as a malformed `NETWORK` value.
- A VPN tunnel whose local/remote networks include both a host and a
  subnet that already contains it (redundant but real ACL entries) gets
  rejected by FTD (`"s2sOverlapChosenNetworks"`) -- the parser now drops
  entries subsumed by a broader one in the same list.
- Several IKE/PFS enum values were simply spelled wrong (`3DES` should be
  `THREE_DES` for policies but `ESP_3DES` -- not `ESP_THREE_DES` -- for
  IKEv1 proposals; `ESP_AES256`/`ESP_AES192`, no underscore before the
  number).
- This FTD build runs in a "strong encryption" mode that hard-rejects DES
  and certain DH groups (1, 2 for IKEv1 policies; 1, 2, 24 for IKEv2
  policies; 1, 2, 24 for PFS) outright, and separately caps IKEv2 policies
  at 20 enabled. These aren't mapping bugs -- the scripts now skip what
  can't be created (weak IKE policies), substitute a safe default where
  there's a sensible one (PFS), and drop just the unsupported cipher from a
  multi-value list rather than failing the whole proposal (IKEv2 IPsec
  proposals) -- but a policy that only ever offered DES, or a priority
  colliding with an existing default policy, gets reported clearly rather
  than silently worked around.
- **PFS group 5 is genuinely fine, despite what FTD's own error text
  claims.** A 422 rejecting `GROUP24` for PFS returns "The following
  Diffie-Hellman groups can no longer be used for Perfect Forward Secrecy:
  1, 2, 5, 24" -- but a direct live PUT of `diffieHellmanGroup: "GROUP5"`
  on a real connection profile succeeded with no error. That error message
  is misleading; only 1, 2, and 24 are actually enforced. 12 tunnels that
  had been substituted to `GROUP14` because of this were corrected back to
  their real ASA-configured `GROUP5` once this was found.
- New rules created via the API can collide in **priority** with FTD's own
  built-in default IKE policies -- `migrate_s2s_vpn.py` now retries once at
  `priority + 1000` on that specific error.

## Order of operations / re-runs

All ten migration scripts (`migrate_logging.py` is a report, not a
migration -- see "Logging") are idempotent: re-running looks up existing
objects and reuses them (`options.skip_existing: true`) rather than erroring
or duplicating, so you can fix a mapping and re-run freely --
`migrate_network_objects.py`/`migrate_routes.py`/`migrate_s2s_vpn.py`/
`migrate_access_control.py`/`migrate_dns.py` do this by name,
`migrate_nat.py`, `migrate_snmp.py`, `migrate_icmp.py`, and
`migrate_http_access.py` don't have a natural unique name to key on so
each does its own equivalent reuse check (see their sections above --
`migrate_nat.py`/`migrate_snmp.py` confirmed live, ICMP/HTTPS access
unverified). `migrate_ntp.py` isn't name-keyed either, but it's a
settings-update (PUT), not a create, so re-running it is inherently
idempotent -- it just re-applies the same server list (confirmed live: one
of the two NTP objects on this device updates cleanly every time, the other
consistently rejects the write with the same error). `migrate_access_control.py`
reads each tunnel's `nat_exempt_interface` from `parsed/vpn.json` to decide
which zones to include, so run it after `migrate_s2s_vpn.py`. `migrate_nat.py`
only needs network objects to already exist (from `migrate_network_objects.py`)
and can run any time after that. `migrate_dns.py`, `migrate_snmp.py`,
`migrate_ntp.py`, `migrate_icmp.py`, and `migrate_http_access.py` are all
independent of every other script and can run any time. `migrate_nat.py`,
`migrate_icmp.py`, and `migrate_http_access.py` are the scripts left that
are only dry-run tested -- run them last, once everything else is confirmed
working, and read their sections above first (HTTPS management access in
particular, given the blast radius of getting device-management access
wrong).
