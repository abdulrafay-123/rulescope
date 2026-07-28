"""EVE JSON alert correlation with enriched rules."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rulescope.models import EnrichedRule, EveAlertView


def _index_rules(rules: list[EnrichedRule]) -> dict[int, EnrichedRule]:
    return {r.sid: r for r in rules}


def parse_eve_file(path: str | Path) -> list[dict[str, Any]]:
    path = Path(path)
    events: list[dict[str, Any]] = []
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return events
    # Support JSON array or NDJSON
    if text.startswith("["):
        data = json.loads(text)
        if isinstance(data, list):
            return [e for e in data if isinstance(e, dict)]
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            events.append(obj)
    return events


def correlate_alerts(
    events: list[dict[str, Any]],
    rules: list[EnrichedRule],
    *,
    alerts_only: bool = True,
) -> list[EveAlertView]:
    by_sid = _index_rules(rules)
    views: list[EveAlertView] = []
    for event in events:
        if alerts_only and event.get("event_type") not in {None, "alert"}:
            # Accept events that have alert object even without event_type
            if "alert" not in event:
                continue
        alert = event.get("alert") or {}
        sid = alert.get("signature_id") or alert.get("sid")
        try:
            sid_int = int(sid) if sid is not None else None
        except (TypeError, ValueError):
            sid_int = None
        rule = by_sid.get(sid_int) if sid_int is not None else None
        views.append(
            EveAlertView(
                timestamp=event.get("timestamp"),
                src_ip=event.get("src_ip"),
                dest_ip=event.get("dest_ip"),
                src_port=event.get("src_port"),
                dest_port=event.get("dest_port"),
                proto=event.get("proto"),
                signature=alert.get("signature") or (rule.msg if rule else None),
                signature_id=sid_int,
                category=alert.get("category"),
                severity=alert.get("severity"),
                rule=rule,
                extras={
                    k: event.get(k)
                    for k in ("flow_id", "community_id", "app_proto", "http", "tls", "dns")
                    if k in event
                },
            )
        )
    return views
