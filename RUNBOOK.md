# Migration runbook

Quick-reference checklist for running the migration in order. For the "why"
behind any step, see `README.md`; for known open issues on this specific
migration, see `REMAINING_ACTIONS.md`.

Separately, `normalize_asa_config.py` is a standalone cleanup tool (resolves
`name` aliases and promotes raw object-group literals to proper `object
network`s) that isn't part of this pipeline -- none of the steps below read
its output. See "ASA config normalizer" in `README.md` if you want to run
it on your ASA export first.

Also separate: `find_unused_objects.py` reports `object network`/
`object-group network` definitions never referenced anywhere else in the
config, as a cleanup candidate list -- also not part of this pipeline. See
"Unused objects report" in `README.md`.

All scripts are idempotent (`options.skip_existing: true`) -- re-running any
step after fixing something is safe, existing objects are reused, not
duplicated. Every script ends by asking `Deploy these changes to the device
now? [y/N]` -- answer **N** until you've completed step 13 below; everything
stays staged as pending changes in FDM either way. Exception: `migrate_logging.py`
never asks -- it's a report, not a migration (see step 11).

## 0. Prerequisites

- [ ] `py -m pip install -r requirements.txt`
- [ ] `copy config.example.yaml config.yaml`, then fill in:
  - `ftd.host` / `username` / `password`
  - `interface_map` (ASA `nameif` -> FTD logical interface name -- get FTD
    names from Device > Interfaces in FDM)
  - `options.dry_run: true` to start
- [ ] On the ASA: `show running-config` > save as `asa-config.txt`

## 1. Parse the ASA config

```
py parse_asa_config.py asa-config.txt --out-dir parsed/
```

Review before continuing:
- `parsed/unparsed_lines.json` -- anything the parser couldn't handle
- `parsed/vpn.json` -- any `UNRESOLVED`/`OBJECT:` markers, any
  `nat_exempt: false` tunnel
- `vpn_secrets.yaml` / `snmp_secrets.yaml` were generated (gitignored) --
  fill in by hand anything the parser couldn't extract a secret for

## 2. Network objects (routes/VPN/ACP/NAT/SNMP all depend on this)

```
py migrate_network_objects.py --config config.yaml --in-dir parsed/
```

## 3. Static routes

```
py migrate_routes.py --config config.yaml --in-dir parsed/
```

## 4. Site-to-site VPN (includes NAT exemption automatically)

```
py migrate_s2s_vpn.py --config config.yaml --in-dir parsed/
```

## 5. Access Control rules for VPN traffic

```
py migrate_access_control.py --config config.yaml --in-dir parsed/
```

**Before deploying anything**, check rule order in FDM -- a new rule
appended after an existing catch-all deny is never evaluated.

## 6. DNS

```
py migrate_dns.py --config config.yaml --in-dir parsed/
```

## 7. SNMP

```
py migrate_snmp.py --config config.yaml --in-dir parsed/
```

## 8. NTP

```
py migrate_ntp.py --config config.yaml --in-dir parsed/
```

Confirmed live. Read "NTP" in `README.md` for one real quirk: this device
returns two NTP settings objects, and only one of them is actually
writable -- the script handles this automatically, but the printed output
will show one object updated and one rejected, which is expected.

## 9. General NAT/PAT (optional -- run last, read README first)

```
py migrate_nat.py --config config.yaml --in-dir parsed/
```

This is the least-tested script in the toolkit -- read "General NAT/PAT" in
`README.md` and dry-run it carefully before a live push.

## 10. ICMP control-plane access (who may ping the device itself)

```
py migrate_icmp.py --config config.yaml --in-dir parsed/
```

Unverified against a live device -- read "ICMP control-plane access" in
`README.md`. Also watch for a printed warning about unreachable entries
(a `deny any` earlier in the list for the same interface) -- that's a real
finding about the ASA config, not a script bug.

## 11. HTTPS management access (who may reach FDM's own web UI)

```
py migrate_http_access.py --config config.yaml --in-dir parsed/
```

Unverified against a live device, and higher-stakes than most of this
toolkit's guesses -- getting it wrong can lock out admin access or expose
the management UI too broadly. Read "HTTPS management access" in
`README.md` before a live run.

## 12. Logging (report only, nothing is pushed)

```
py migrate_logging.py --in-dir parsed/
```

Prints ASA's `logging from-address`/`ftp-server` settings for your own
reference. `ftp-server` is **confirmed not supported** on FTD/FDM (use an
external syslog server/SIEM instead); `from-address` remains unconfirmed.
Read "Logging" in `README.md`.

## 13. Review and deploy

- [ ] Open FDM's **Pending Changes** view and skim the full diff
- [ ] Resolve everything open in `REMAINING_ACTIONS.md`
- [ ] Deploy from FDM (or answer `y` to the next script's deploy prompt)

## Order, visually

```
1. parse_asa_config.py
2. migrate_network_objects.py
3. migrate_routes.py
4. migrate_s2s_vpn.py             (needs step 2)
5. migrate_access_control.py      (needs step 4)
6. migrate_dns.py                 (needs step 2 only -- can run any time after)
7. migrate_snmp.py                (needs step 2 only -- can run any time after)
8. migrate_ntp.py                 (independent -- can run any time; confirmed live)
9. migrate_nat.py                 (needs step 2 only -- optional, least-tested, run last)
10. migrate_icmp.py               (needs step 2 only -- unverified, run last)
11. migrate_http_access.py        (needs step 2 only -- unverified, run last, high-stakes)
12. migrate_logging.py            (independent -- report only, no push)
13. review pending changes + deploy
```
