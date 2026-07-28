"""Enrich Suricata rules with CVE, MITRE, platforms, severity, age."""

from __future__ import annotations

import re
from datetime import date, datetime

from rulescope.models import EnrichedRule

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
DATE_RE = re.compile(r"^(\d{4})[_-](\d{2})[_-](\d{2})$")

SEVERITY_FROM_CLASSTYPE = {
    "attempted-admin": "high",
    "successful-admin": "critical",
    "attempted-user": "high",
    "successful-user": "high",
    "shellcode-detect": "critical",
    "trojan-activity": "high",
    "web-application-attack": "high",
    "attempted-dos": "medium",
    "denial-of-service": "medium",
    "policy-violation": "low",
    "not-suspicious": "info",
    "unknown": "unknown",
    "misc-activity": "low",
    "misc-attack": "medium",
    "icmp-event": "info",
    "bad-unknown": "medium",
    "targeted-activity": "high",
    "exploit-kit": "high",
    "external-ip-check": "low",
    "domain-c2": "high",
    "pup-activity": "low",
}

PLATFORM_HINTS = {
    "windows": ["windows", "win32", "win64", "smb", "rdp", "kerberos", "lsass", "powershell"],
    "linux": ["linux", "unix", "bash", "elf ", "ssh"],
    "macos": ["macos", "osx", "darwin"],
    "android": ["android", "apk"],
    "ios": ["iphone", "ios "],
    "scada": ["scada", "modbus", "dnp3", "iec104", "bacnet", "opc"],
    "network": ["router", "cisco", "juniper", "snmp"],
}

SERVICE_HINTS = {
    "http": ["http", "apache", "nginx", "iis", "web"],
    "dns": ["dns", "bind", "domain"],
    "tls": ["tls", "ssl", "https", "x509"],
    "ssh": ["ssh", "openssh"],
    "smb": ["smb", "cifs", "samba"],
    "smtp": ["smtp", "mail", "imap", "pop3"],
    "ftp": ["ftp"],
    "rdp": ["rdp", "remote desktop"],
    "database": ["sql", "mysql", "postgres", "oracle", "mssql"],
}


def _parse_date(value: str) -> date | None:
    value = value.strip()
    m = DATE_RE.match(value)
    if m:
        try:
            return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except ValueError:
            return None
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%Y_%m_%d"):
        try:
            return datetime.strptime(value, fmt).date()
        except ValueError:
            continue
    return None


def _first_meta(rule: EnrichedRule, *keys: str) -> str | None:
    for key in keys:
        vals = rule.metadata.get(key)
        if vals:
            return vals[0]
    return None


_SEVERITY_ALIASES = {
    "critical": "critical",
    "high": "high",
    "major": "high",
    "medium": "medium",
    "minor": "low",
    "low": "low",
    "info": "info",
    "informational": "info",
}


def _severity(rule: EnrichedRule) -> str:
    for key in ("signature_severity", "severity"):
        vals = rule.metadata.get(key, [])
        for val in vals:
            mapped = _SEVERITY_ALIASES.get(val.lower())
            if mapped:
                return mapped
    if rule.priority is not None:
        if rule.priority <= 1:
            return "critical"
        if rule.priority == 2:
            return "high"
        if rule.priority == 3:
            return "medium"
        return "low"
    return SEVERITY_FROM_CLASSTYPE.get(rule.classtype.lower(), "unknown")


def _extract_cves(rule: EnrichedRule) -> list[str]:
    found: list[str] = []
    blob = " ".join(
        [rule.msg, rule.raw, " ".join(rule.reference), " ".join(sum(rule.metadata.values(), []))]
    )
    for match in CVE_RE.findall(blob):
        cve = match.upper()
        if cve not in found:
            found.append(cve)
    for ref in rule.reference:
        if ref.lower().startswith("cve,"):
            num = ref.split(",", 1)[1].strip()
            cve = num if num.upper().startswith("CVE-") else f"CVE-{num}"
            cve = cve.upper()
            if cve not in found:
                found.append(cve)
    return found


def _extract_mitre(rule: EnrichedRule) -> list[str]:
    tags: list[str] = []
    for key, vals in rule.metadata.items():
        if "mitre" in key or key in {"attack_target", "tactic", "technique"}:
            for val in vals:
                token = val.strip()
                if token and token not in tags:
                    tags.append(token)
        if key.startswith("malware_") or key in {"former_category", "deployment"}:
            continue
    # Common ET metadata keys
    for key in ("mitre_tactic_id", "mitre_technique_id", "mitre_tactic_name", "mitre_technique_name"):
        for val in rule.metadata.get(key, []):
            if val not in tags:
                tags.append(val)
    return tags


def _infer_tokens(rule: EnrichedRule, hints: dict[str, list[str]]) -> list[str]:
    blob = f"{rule.msg} {rule.raw} {rule.protocol} {' '.join(sum(rule.metadata.values(), []))}".lower()
    hits: list[str] = []
    for label, needles in hints.items():
        if any(n in blob for n in needles):
            hits.append(label)
    # Explicit metadata
    for key in ("os", "target_os", "platform", "affected_product"):
        for val in rule.metadata.get(key, []):
            low = val.lower()
            for label in hints:
                if label in low and label not in hits:
                    hits.append(label)
    return hits


def enrich_rule(rule: EnrichedRule, today: date | None = None) -> EnrichedRule:
    today = today or date.today()
    rule.cves = _extract_cves(rule)
    rule.mitre = _extract_mitre(rule)
    rule.platforms = _infer_tokens(rule, PLATFORM_HINTS) or ["network"]
    rule.services = _infer_tokens(rule, SERVICE_HINTS)
    rule.severity = _severity(rule)

    created = _first_meta(rule, "created_at", "created", "date")
    updated = _first_meta(rule, "updated_at", "updated", "last_modified")
    rule.created_at = _parse_date(created) if created else None
    rule.updated_at = _parse_date(updated) if updated else rule.created_at

    anchor = rule.updated_at or rule.created_at
    if anchor:
        rule.age_days = (today - anchor).days
        # Heuristic: exploit/info rules untouched for 8+ years flagged outdated
        rule.outdated = rule.age_days > 2920 and rule.severity in {"low", "info", "unknown", "medium"}
    else:
        # No date: outdated unknown; mark soft outdated for ancient CVE years
        years = [int(cve.split("-")[1]) for cve in rule.cves if cve.startswith("CVE-")]
        if years and max(years) < today.year - 10:
            rule.outdated = True
            rule.age_days = (today.year - max(years)) * 365
    return rule


def enrich_rules(rules: list[EnrichedRule], today: date | None = None) -> list[EnrichedRule]:
    return [enrich_rule(rule, today=today) for rule in rules]
