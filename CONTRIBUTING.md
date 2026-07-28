# Contributing to RuleScope

Thanks for helping improve open-source Suricata tooling.

## Dev setup

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
```

## Guidelines

- Keep the core CLI usable without the web UI.
- Prefer exporting `suricata-update` compatible configs over inventing new formats.
- Add sample fixtures under `samples/` for new parsers or enrichers.
- Include a focused pytest for behavior changes.

## Scope

RuleScope targets ruleset intelligence and tuning exports. Fleet provisioning and full TI platforms are out of scope for v1.
