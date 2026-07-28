# RuleScope roadmap

## v0.1 (shipped)

- [x] Suricata rule parser (enabled + `#`-disabled)
- [x] Enrichment: CVE, severity, platforms, services, age, outdated heuristic
- [x] Asset-profile relevance scoring
- [x] Web workbench + CLI
- [x] EVE alert correlation
- [x] `disable.conf` / `enable.conf` export
- [x] Demo samples + tests + Docker
- [x] Ruleset diff (`rulescope diff`) for post-update hygiene
- [x] Persist catalogs in SQLite (`rulescope index` / `query`)

## v0.2

- [ ] Bulk import Emerging Threats Open / custom rules directories with progress
- [ ] OPNsense policy export helpers
- [ ] Better MITRE ATT&CK technique name resolution
- [ ] Web UI for ruleset diff
- [ ] Streaming index progress for 100k+ SID imports

## v0.3

- [ ] Multi-profile comparison (perimeter vs internal vs OT)
- [ ] Alert volume feedback loop (tune relevance from EVE history)
- [ ] Optional Suricata Language Server / `suricata -T` validation hook
- [ ] GitHub Action for ruleset hygiene checks

## Non-goals

- Replacing IDSTower cluster provisioning
- Full threat-intel platform (MISP/TAXII hub)
- Competing with Clear NDR / SELKS dashboards
