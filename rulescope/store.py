"""SQLite catalog persistence for large Suricata rulesets."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from rulescope.models import AssetProfile, EnrichedRule
from rulescope.pipeline import build_catalog

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rules (
  sid INTEGER PRIMARY KEY,
  gid INTEGER NOT NULL,
  rev INTEGER NOT NULL,
  msg TEXT NOT NULL,
  classtype TEXT,
  severity TEXT,
  relevance_score REAL,
  relevance_label TEXT,
  platforms TEXT,
  services TEXT,
  cves TEXT,
  mitre TEXT,
  outdated INTEGER,
  enabled INTEGER,
  age_days INTEGER,
  raw TEXT,
  payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rules_severity ON rules(severity);
CREATE INDEX IF NOT EXISTS idx_rules_relevance ON rules(relevance_label);
CREATE INDEX IF NOT EXISTS idx_rules_msg ON rules(msg);
"""


def _connect(db_path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str | Path) -> None:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _connect(path) as conn:
        conn.executescript(SCHEMA)


def index_catalog(
    db_path: str | Path,
    rules_paths: list[str | Path],
    profile: AssetProfile | None = None,
) -> dict:
    """Build/replace a SQLite catalog from rules paths."""
    profile = profile or AssetProfile()
    rules, summary = build_catalog(rules_paths, profile)
    init_db(db_path)
    with _connect(db_path) as conn:
        conn.execute("DELETE FROM rules")
        conn.execute("DELETE FROM meta")
        conn.execute(
            "INSERT INTO meta(key, value) VALUES (?, ?)",
            ("summary", json.dumps(summary.model_dump(mode="json"))),
        )
        conn.execute(
            "INSERT INTO meta(key, value) VALUES (?, ?)",
            ("profile", json.dumps(profile.model_dump(mode="json"))),
        )
        rows = []
        for rule in rules:
            payload = json.dumps(rule.model_dump(mode="json"))
            rows.append(
                (
                    rule.sid,
                    rule.gid,
                    rule.rev,
                    rule.msg,
                    rule.classtype,
                    rule.severity,
                    rule.relevance_score,
                    rule.relevance_label,
                    json.dumps(rule.platforms),
                    json.dumps(rule.services),
                    json.dumps(rule.cves),
                    json.dumps(rule.mitre),
                    1 if rule.outdated else 0,
                    1 if rule.enabled else 0,
                    rule.age_days,
                    rule.raw,
                    payload,
                )
            )
        conn.executemany(
            """
            INSERT INTO rules(
              sid, gid, rev, msg, classtype, severity, relevance_score, relevance_label,
              platforms, services, cves, mitre, outdated, enabled, age_days, raw, payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        conn.commit()
    return summary.model_dump(mode="json")


def query_catalog(
    db_path: str | Path,
    *,
    q: str | None = None,
    severity: str | None = None,
    relevance: str | None = None,
    limit: int = 50,
) -> list[EnrichedRule]:
    init_db(db_path)
    clauses: list[str] = []
    params: list[object] = []
    if q:
        clauses.append("(msg LIKE ? OR CAST(sid AS TEXT) LIKE ? OR cves LIKE ?)")
        like = f"%{q}%"
        params.extend([like, like, like])
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if relevance:
        clauses.append("relevance_label = ?")
        params.append(relevance)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = f"""
      SELECT payload FROM rules
      {where}
      ORDER BY relevance_score DESC, sid ASC
      LIMIT ?
    """
    params.append(limit)
    with _connect(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
    return [EnrichedRule.model_validate_json(row["payload"]) for row in rows]


def catalog_summary(db_path: str | Path) -> dict:
    init_db(db_path)
    with _connect(db_path) as conn:
        row = conn.execute("SELECT value FROM meta WHERE key = 'summary'").fetchone()
        count = conn.execute("SELECT COUNT(*) AS n FROM rules").fetchone()["n"]
    if row:
        data = json.loads(row["value"])
        data["indexed_rows"] = count
        return data
    return {"total_rules": count, "indexed_rows": count}
