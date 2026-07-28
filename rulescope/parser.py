"""Suricata / Snort-style rule parser."""

from __future__ import annotations

import re
from pathlib import Path

from rulescope.models import EnrichedRule

HEADER_RE = re.compile(
    r"^(?P<disabled>#\s*)?(?P<action>alert|drop|reject|pass|rejectsrc|rejectdst)\s+"
    r"(?P<protocol>\S+)\s+"
    r"(?P<src>\S+)\s+(?P<sport>\S+)\s+"
    r"(?P<direction>->|<>)\s+"
    r"(?P<dst>\S+)\s+(?P<dport>\S+)\s*"
    r"\((?P<body>.*)\)\s*$",
    re.IGNORECASE | re.DOTALL,
)

OPTION_RE = re.compile(
    r"(?P<key>[a-zA-Z0-9_.-]+)\s*:\s*(?P<value>(?:\".*?\"|[^;]+))\s*;|"
    r"(?P<flag>[a-zA-Z0-9_.-]+)\s*;",
    re.DOTALL,
)


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _parse_options(body: str) -> tuple[dict[str, list[str]], set[str]]:
    options: dict[str, list[str]] = {}
    flags: set[str] = set()
    for match in OPTION_RE.finditer(body):
        if match.group("flag"):
            flags.add(match.group("flag").lower())
            continue
        key = match.group("key").lower()
        value = _unquote(match.group("value"))
        options.setdefault(key, []).append(value)
    return options, flags


def parse_rule_line(line: str, source_file: str | None = None) -> EnrichedRule | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") and "alert" not in stripped.lower():
        # allow "# alert ..." disabled rules
        if not re.match(r"^#\s*(alert|drop|reject|pass)\b", stripped, re.I):
            return None

    match = HEADER_RE.match(stripped)
    if not match:
        return None

    options, _flags = _parse_options(match.group("body"))
    sid_vals = options.get("sid", ["0"])
    try:
        sid = int(sid_vals[0])
    except ValueError:
        return None

    gid = int(options.get("gid", ["1"])[0])
    rev = int(options.get("rev", ["1"])[0])
    priority = None
    if "priority" in options:
        try:
            priority = int(options["priority"][0])
        except ValueError:
            priority = None

    metadata: dict[str, list[str]] = {}
    for raw in options.get("metadata", []):
        for part in raw.split(","):
            part = part.strip()
            if not part:
                continue
            if " " in part:
                key, val = part.split(" ", 1)
                metadata.setdefault(key.strip().lower(), []).append(val.strip())
            else:
                metadata.setdefault(part.lower(), []).append("true")

    return EnrichedRule(
        sid=sid,
        gid=gid,
        rev=rev,
        action=match.group("action").lower(),
        protocol=match.group("protocol").lower(),
        src=match.group("src"),
        src_port=match.group("sport"),
        direction=match.group("direction"),
        dst=match.group("dst"),
        dst_port=match.group("dport"),
        msg=options.get("msg", [""])[0],
        classtype=options.get("classtype", [""])[0],
        priority=priority,
        enabled=match.group("disabled") is None,
        raw=stripped.lstrip("# ").strip() if match.group("disabled") else stripped,
        reference=options.get("reference", []),
        metadata=metadata,
        source_file=source_file,
    )


def parse_rules_text(text: str, source_file: str | None = None) -> list[EnrichedRule]:
    rules: list[EnrichedRule] = []
    # Join continued lines ending with \
    logical_lines: list[str] = []
    buf = ""
    for line in text.splitlines():
        if line.rstrip().endswith("\\"):
            buf += line.rstrip()[:-1] + " "
            continue
        buf += line
        logical_lines.append(buf)
        buf = ""
    if buf.strip():
        logical_lines.append(buf)

    for line in logical_lines:
        rule = parse_rule_line(line, source_file=source_file)
        if rule:
            rules.append(rule)
    return rules


def parse_rules_file(path: str | Path) -> list[EnrichedRule]:
    path = Path(path)
    return parse_rules_text(path.read_text(encoding="utf-8", errors="replace"), source_file=str(path))


def parse_rules_paths(paths: list[str | Path]) -> list[EnrichedRule]:
    rules: list[EnrichedRule] = []
    for path in paths:
        p = Path(path)
        if p.is_dir():
            for child in sorted(p.rglob("*.rules")):
                rules.extend(parse_rules_file(child))
        else:
            rules.extend(parse_rules_file(p))
    # Prefer first occurrence of SID
    seen: set[int] = set()
    unique: list[EnrichedRule] = []
    for rule in rules:
        if rule.sid in seen:
            continue
        seen.add(rule.sid)
        unique.append(rule)
    return unique
