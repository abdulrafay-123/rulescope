# RuleScope roadmap

## v0.1 (shipped)

- [x] Suricata rule parser (enabled + `#`-disabled)
- [x] Enrichment: CVE, severity, platforms, services, age, outdated heuristic
- [x] Asset-profile relevance scoring
- [x] Web workbench + CLI
- [x] EVE alert correlation
- [x] `disable.conf` / `enable.conf` export
- [x] Demo samples + tests + Docker

## v0.2

- [ ] Bulk import Emerging Threats Open / custom rules directories with progress
- [ ] Persist catalogs in SQLite for large rulesets (100k+ SIDs)
- [ ] OPNsense policy export helpers
- [ ] Better MITRE ATT&CK technique name resolution
- [ ] Diff two rulesets / show what changed after `suricata-update`

## v0.3

- [ ] Multi-profile comparison (perimeter vs internal vs OT)
- [ ] Alert volume feedback loop (tune relevance from EVE history)
- [ ] Optional Suricata Language Server / `suricata -T` validation hook
- [ ] GitHub Action for ruleset hygiene checks

## Non-goals

- Replacing IDSTower cluster provisioning
- Full threat-intel platform (MISP/TAXII hub)
- Competing with Clear NDR / SELKS dashboards
