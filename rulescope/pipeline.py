"""High-level pipeline helpers."""

from __future__ import annotations

import json
from pathlib import Path

from rulescope.enrich import enrich_rules
from rulescope.export import render_disable_conf, render_enable_conf, rules_to_dicts
from rulescope.models import AssetProfile, CatalogSummary, EnrichedRule
from rulescope.parser import parse_rules_paths
from rulescope.relevance import disable_candidates, score_rules, summarize


def load_profile(path: str | Path | None) -> AssetProfile:
    if path is None:
        return AssetProfile()
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return AssetProfile.model_validate(data)


def build_catalog(
    rules_paths: list[str | Path],
    profile: AssetProfile | None = None,
) -> tuple[list[EnrichedRule], CatalogSummary]:
    profile = profile or AssetProfile()
    rules = parse_rules_paths(rules_paths)
    rules = enrich_rules(rules)
    rules = score_rules(rules, profile)
    rules.sort(key=lambda r: (-r.relevance_score, r.sid))
    return rules, summarize(rules)


def analyze_to_dict(
    rules_paths: list[str | Path],
    profile: AssetProfile | None = None,
) -> dict:
    rules, summary = build_catalog(rules_paths, profile)
    return {
        "summary": summary.model_dump(mode="json"),
        "profile": (profile or AssetProfile()).model_dump(mode="json"),
        "rules": rules_to_dicts(rules),
    }


def make_disable_conf(
    rules_paths: list[str | Path],
    profile: AssetProfile | None = None,
    *,
    max_score: float = 30.0,
) -> str:
    rules, _ = build_catalog(rules_paths, profile)
    return render_disable_conf(disable_candidates(rules, max_score=max_score))


def make_enable_conf(
    rules_paths: list[str | Path],
    profile: AssetProfile | None = None,
    *,
    min_score: float = 70.0,
) -> str:
    rules, _ = build_catalog(rules_paths, profile)
    keep = [r for r in rules if r.relevance_score >= min_score]
    return render_enable_conf(keep)
