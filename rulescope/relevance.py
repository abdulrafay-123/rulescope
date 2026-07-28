"""Asset-aware relevance scoring for Suricata rules."""

from __future__ import annotations

from collections import Counter

from rulescope.models import AssetProfile, CatalogSummary, EnrichedRule

SEVERITY_WEIGHT = {
    "critical": 35,
    "high": 28,
    "medium": 18,
    "low": 8,
    "info": 4,
    "unknown": 10,
}


def score_rule(rule: EnrichedRule, profile: AssetProfile) -> EnrichedRule:
    score = 40.0
    reasons: list[str] = []

    # Severity baseline
    sev = rule.severity.lower()
    score += SEVERITY_WEIGHT.get(sev, 10)
    reasons.append(f"severity:{sev}")

    # Platform fit
    profile_platforms = {p.lower() for p in profile.platforms}
    exclude_platforms = {p.lower() for p in profile.exclude_platforms}
    rule_platforms = {p.lower() for p in rule.platforms}

    if rule_platforms & exclude_platforms:
        score -= 45
        reasons.append("matches excluded platform")
    elif rule_platforms & profile_platforms:
        score += 20
        reasons.append("platform matches asset profile")
    elif rule_platforms <= {"network"}:
        score += 8
        reasons.append("generic network rule")
    else:
        score -= 25
        reasons.append("platform unlikely in environment")

    # Service fit
    profile_services = {s.lower() for s in profile.services}
    exclude_services = {s.lower() for s in profile.exclude_services}
    rule_services = {s.lower() for s in rule.services}

    if rule_services & exclude_services:
        score -= 20
        reasons.append("matches excluded service")
    elif rule_services & profile_services:
        score += 15
        reasons.append("service matches asset profile")
    elif rule_services:
        score -= 10
        reasons.append("service not declared in profile")

    # CVE / recency
    if rule.cves:
        score += 8
        reasons.append("has CVE reference")
    if rule.outdated:
        score -= 18
        reasons.append("likely outdated")
    elif rule.age_days is not None and rule.age_days < 365:
        score += 10
        reasons.append("updated within last year")

    # Deployment / role metadata
    deployments = {v.lower() for v in rule.metadata.get("deployment", [])}
    roles = {r.lower() for r in profile.roles}
    if deployments and roles and deployments & roles:
        score += 8
        reasons.append("deployment role matches")

    # Disabled upstream
    if not rule.enabled:
        score -= 5
        reasons.append("disabled in source ruleset")

    score = max(0.0, min(100.0, score))
    if score >= 70:
        label = "high"
    elif score >= 45:
        label = "medium"
    elif score >= 25:
        label = "low"
    else:
        label = "noise"

    rule.relevance_score = round(score, 1)
    rule.relevance_label = label
    rule.relevance_reasons = reasons
    return rule


def score_rules(rules: list[EnrichedRule], profile: AssetProfile) -> list[EnrichedRule]:
    return [score_rule(rule, profile) for rule in rules]


def summarize(rules: list[EnrichedRule]) -> CatalogSummary:
    by_sev: Counter[str] = Counter(r.severity for r in rules)
    by_rel: Counter[str] = Counter(r.relevance_label for r in rules)
    platforms: Counter[str] = Counter()
    for rule in rules:
        for p in rule.platforms:
            platforms[p] += 1
    return CatalogSummary(
        total_rules=len(rules),
        enabled=sum(1 for r in rules if r.enabled),
        disabled=sum(1 for r in rules if not r.enabled),
        with_cve=sum(1 for r in rules if r.cves),
        high_severity=sum(1 for r in rules if r.severity in {"high", "critical"}),
        outdated=sum(1 for r in rules if r.outdated),
        by_severity=dict(by_sev),
        by_relevance=dict(by_rel),
        top_platforms=dict(platforms.most_common(10)),
    )


def disable_candidates(
    rules: list[EnrichedRule],
    *,
    max_score: float = 30.0,
    include_outdated: bool = True,
) -> list[EnrichedRule]:
    out: list[EnrichedRule] = []
    for rule in rules:
        if rule.relevance_score <= max_score:
            out.append(rule)
        elif include_outdated and rule.outdated and rule.relevance_label in {"low", "noise"}:
            out.append(rule)
    return sorted(out, key=lambda r: (r.relevance_score, r.sid))
