"""Diff two Suricata rulesets by SID."""

from __future__ import annotations

from dataclasses import dataclass, field

from rulescope.models import EnrichedRule


@dataclass
class RulesetDiff:
    added: list[EnrichedRule] = field(default_factory=list)
    removed: list[EnrichedRule] = field(default_factory=list)
    changed: list[dict] = field(default_factory=list)
    unchanged: int = 0

    def to_dict(self) -> dict:
        return {
            "added": [r.model_dump(mode="json") for r in self.added],
            "removed": [r.model_dump(mode="json") for r in self.removed],
            "changed": self.changed,
            "unchanged": self.unchanged,
            "summary": {
                "added": len(self.added),
                "removed": len(self.removed),
                "changed": len(self.changed),
                "unchanged": self.unchanged,
            },
        }


def diff_rulesets(old: list[EnrichedRule], new: list[EnrichedRule]) -> RulesetDiff:
    old_map = {r.sid: r for r in old}
    new_map = {r.sid: r for r in new}
    result = RulesetDiff()

    for sid, rule in new_map.items():
        if sid not in old_map:
            result.added.append(rule)
            continue
        prev = old_map[sid]
        changes: dict[str, dict[str, str | int | bool]] = {}
        for field_name in ("msg", "rev", "classtype", "enabled", "raw"):
            if getattr(prev, field_name) != getattr(rule, field_name):
                changes[field_name] = {
                    "old": getattr(prev, field_name),
                    "new": getattr(rule, field_name),
                }
        if changes:
            result.changed.append({"sid": sid, "msg": rule.msg, "changes": changes})
        else:
            result.unchanged += 1

    for sid, rule in old_map.items():
        if sid not in new_map:
            result.removed.append(rule)

    result.added.sort(key=lambda r: r.sid)
    result.removed.sort(key=lambda r: r.sid)
    result.changed.sort(key=lambda c: c["sid"])
    return result
