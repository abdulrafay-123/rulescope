# Using RuleScope with OPNsense

OPNsense's Suricata plugin is great for getting IDS running, but its rule list UI is hard to triage (SIDs without context). RuleScope fills that gap offline, then feeds decisions back through `suricata-update`.

## Recommended workflow

1. Export / copy your active ruleset (or download ET Open) onto a workstation.
2. Create an asset profile that matches your network (`linux`/`windows`, services, exclude OT if unused).
3. Analyze:

```bash
rulescope analyze /path/to/rules --profile homelab.json -o report.json
```

4. Export OPNsense-oriented helpers:

```bash
rulescope export-opnsense /path/to/rules --profile homelab.json --outdir ./out
```

This writes:

- `disable.conf` — drop into suricata-update
- `opnsense-policy.json` — SID buckets: disable / keep / review
- `opnsense-review.csv` — spreadsheet-friendly triage list

5. On OPNsense, prefer the community `suricata-update` approach (see [Nova-Labs writeup](https://forum.suricata.io/t/request-for-enhanced-rule-management-interface-in-suricata/5867)) and apply the generated `disable.conf`.

## Why not edit the OPNsense GUI policy directly?

OPNsense policy management is limited for bulk “irrelevant to my assets” decisions. RuleScope is designed to answer relevance first, then emit configs the official Suricata tooling already understands.
