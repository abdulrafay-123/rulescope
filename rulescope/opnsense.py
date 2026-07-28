"""OPNsense-oriented Suricata policy exports."""

from __future__ import annotations

import csv
import io
import json

from rulescope.models import EnrichedRule
from rulescope.relevance import disable_candidates


def recommend_action(rule: EnrichedRule, *, max_disable_score: float = 30.0) -> str:
    if rule.relevance_score <= max_disable_score or (
        rule.outdated and rule.relevance_label in {"low", "noise"}
    ):
        return "disable"
    if rule.relevance_score >= 70:
        return "keep"
    return "review"


def render_opnsense_csv(
    rules: list[EnrichedRule],
    *,
    max_disable_score: float = 30.0,
) -> str:
    """CSV operators can import/review when tuning OPNsense Suricata policies."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "sid",
            "msg",
            "severity",
            "relevance_label",
            "relevance_score",
            "recommended_action",
            "platforms",
            "cves",
            "reasons",
        ]
    )
    for rule in sorted(rules, key=lambda r: (recommend_action(r, max_disable_score=max_disable_score), r.sid)):
        writer.writerow(
            [
                rule.sid,
                rule.msg,
                rule.severity,
                rule.relevance_label,
                rule.relevance_score,
                recommend_action(rule, max_disable_score=max_disable_score),
                "|".join(rule.platforms),
                "|".join(rule.cves),
                "|".join(rule.relevance_reasons),
            ]
        )
    return buf.getvalue()


def render_opnsense_policy_json(
    rules: list[EnrichedRule],
    *,
    max_disable_score: float = 30.0,
) -> str:
    disable = disable_candidates(rules, max_score=max_disable_score)
    keep = [r for r in rules if recommend_action(r, max_disable_score=max_disable_score) == "keep"]
    review = [r for r in rules if recommend_action(r, max_disable_score=max_disable_score) == "review"]
    payload = {
        "generator": "rulescope",
        "notes": (
            "OPNsense ships its own Suricata policy UI. For advanced tuning, many operators "
            "switch rule management to suricata-update and apply disable.conf/enable.conf. "
            "See docs/OPNSENSE.md."
        ),
        "disable_sids": [r.sid for r in disable],
        "keep_sids": [r.sid for r in keep],
        "review_sids": [r.sid for r in review],
        "counts": {
            "disable": len(disable),
            "keep": len(keep),
            "review": len(review),
        },
    }
    return json.dumps(payload, indent=2) + "\n"
