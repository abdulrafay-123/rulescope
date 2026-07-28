# RuleScope research notes

## Problem statement

Suricata is widely deployed as an open-source IDS/IPS engine, but operators repeatedly report that **rule management UX is the weak link**. IDSTower commercializes cluster + rules + TI management; Aristotle and suricata-update help programmatically; none fully deliver a free, human-first “does this rule matter for my network?” workbench.

## Community signals

### Suricata forum — Enhanced rule management (Jul 2025)

Thread: https://forum.suricata.io/t/request-for-enhanced-rule-management-interface-in-suricata/5867

Operators using Suricata via OPNsense say:

- Interfaces show SIDs / opaque rule text
- No clear severity, affected systems, or relevance
- No indication a rule is outdated
- No “recent exploits only” filtering

Requested at a glance:

- `msg` description
- CVE / Exploit-DB links
- Publication date
- Severity
- Affected systems
- Whether it applies to their network

OISF correctly noted GUI tooling is outside Suricata core — so the gap remains for community tooling.

### OPNsense — GUI rule editor (2025)

https://github.com/opnsense/core/issues/9268

Users need full Suricata syntax editing without SSH, plus validation. Complex detections (exfiltration via `fileext`, PCRE, etc.) are inaccessible to non-CLI admins.

### Suricata forum — FP / exclusions (2022)

https://forum.suricata.io/t/rule-tuning-and-management-exclusions-and-false-positives/2183

New operators struggle with false-positive workflows. The answer is usually `suricata-update` `disable.conf`, but there is no intelligence layer telling you *which* SIDs to disable for your environment. IDSTower replies advertise their free single-host tier — underscoring the missing OSS product.

### IDSTower positioning

https://www.idstower.com/docs/overview.html

IDSTower markets exactly the UI/cluster/rules/IOC gaps of open-source IDS — but remains proprietary (free for 1 host, paid beyond). Features the community wants OSS:

- Analyst visibility into rules without sysadmin gatekeeping
- Carry-forward transforms across ruleset updates
- IOC lifecycle

RuleScope intentionally does **not** clone cluster provisioning. It owns the OSS gap around **understanding + relevance + exportable tuning**.

### Existing OSS landscape

| Project | Role | Gap left |
|---------|------|----------|
| Suricata | Detection engine | No rule intelligence UI |
| suricata-update | Download / enable / disable | No enrichment or asset scoring |
| Aristotle | Metadata CLI filter | No UI, limited asset profiles |
| Scirius | Ruleset + hunting (GPL) | Heavy, SELKS-oriented |
| Suricata Language Server | IDE authoring | Not ops/admin catalog |
| NIDS Editor | Browser editor | No enrichment / relevance / EVE |
| IDSTower | Full management GUI | Not open source |

## RuleScope product thesis

Build the missing open-source layer:

1. **Enrich** every rule into operator language (CVE, severity, platform, age)
2. **Score** relevance against a declared asset profile
3. **Tune** by exporting `disable.conf` / `enable.conf`
4. **Explain** EVE alerts by joining to enriched rules — without requiring Elasticsearch

This helps home labs, SMB OPNsense admins, and SOC juniors who cannot justify IDSTower Pro/Enterprise.

## Non-goals (v1)

- Suricata process orchestration / SSH fleet management
- Full TI/TAXII platform
- Replacing Clear NDR / SELKS dashboards
- Competing with Suricata Language Server for rule authors
