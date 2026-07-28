# RuleScope

**Open-source Suricata ruleset intelligence for humans.**

Suricata is an excellent detection engine with almost no usable rule UX. IDSTower fills that gap commercially, but it is not open source. Community admins (especially on OPNsense and bare Suricata) still ask the same questions:

- What does this SID actually detect?
- How severe is it, and is it outdated?
- Does it apply to *my* network?
- How do I export a sane `disable.conf` for `suricata-update`?

RuleScope answers those questions.

## Why this exists

From Suricata / OPNsense community discussions:

| Pain | Suricata | IDSTower | RuleScope |
|------|----------|----------|-----------|
| SID lists without context | — | paid UI | free, OSS |
| CVE / severity / platform at a glance | raw text | yes | yes |
| Asset-aware relevance (“applies to my stack?”) | no | no | **yes** |
| Analyst FP tuning → `disable.conf` / `enable.conf` | manual | proprietary | **yes** |
| EVE alert + rule context without ELK | no | limited | **yes** |
| Fully open source | engine only | no | **yes** |

RuleScope does **not** try to replace Suricata, IDSTower cluster provisioning, or Scirius/SELKS. It focuses on the missing open-source layer: **ruleset understanding, relevance, and exportable tuning**.

## Features

- Parse Suricata / ET-style `.rules` files into a searchable catalog
- Enrich rules with `msg`, classtype, severity, CVE, MITRE tags, platforms, age
- Score relevance against a simple **asset profile** (OS, services, roles)
- Filter: high severity, recent exploits, irrelevant noise, outdated candidates
- Browse EVE JSON alerts joined to rule intelligence
- Export `disable.conf` / `enable.conf` for `suricata-update`
- Local-first: SQLite optional, works offline from files
- Docker Compose one-liner

## Quick start

```bash
# Python 3.11+
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
# source .venv/bin/activate

pip install -e ".[dev]"
rulescope serve --host 127.0.0.1 --port 8080
```

Open http://127.0.0.1:8080

Or with Docker:

```bash
docker compose up --build
```

## CLI

```bash
# Catalog summary
rulescope analyze samples/rules/demo.rules --profile samples/profiles/homelab.json

# Relevance report (JSON)
rulescope analyze samples/rules/demo.rules --profile samples/profiles/homelab.json -o report.json

# Export disable candidates (low relevance / noise)
rulescope export-disable samples/rules/demo.rules --profile samples/profiles/homelab.json -o disable.conf

# Diff two rulesets after an update
rulescope diff old.rules new.rules -o diff.json

# Correlate EVE alerts
rulescope eve samples/eve/eve-alerts.json --rules samples/rules/demo.rules
```

## Asset profile example

```json
{
  "name": "homelab",
  "platforms": ["linux", "windows"],
  "services": ["http", "dns", "ssh", "smb"],
  "roles": ["perimeter", "internal"],
  "exclude_platforms": ["ios", "android", "scada"]
}
```

## Architecture

```
rulescope/
  parser.py      # Suricata rule lexer/parser
  enrich.py      # CVE, MITRE, severity, age, platforms
  relevance.py   # asset-profile scoring
  eve.py         # EVE JSON alert join
  export.py      # suricata-update conf export
  api.py         # FastAPI + static UI
  cli.py         # Typer CLI
```

## Community gap (research notes)

See [docs/RESEARCH.md](docs/RESEARCH.md) for forum quotes and competitive analysis.

## License

MIT — use it, fork it, improve it with the Suricata community.

## Contributing

Issues and PRs welcome. Priority areas:

1. Better platform inference from rule bodies
2. Emerging Threats / Open ruleset bulk import
3. MITRE ATT&CK mapping completeness
4. OPNsense export helpers
