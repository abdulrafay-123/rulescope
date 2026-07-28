"""Shared data models for RuleScope."""

from __future__ import annotations

from datetime import date
from typing import Any

from pydantic import BaseModel, Field


class AssetProfile(BaseModel):
    name: str = "default"
    platforms: list[str] = Field(default_factory=lambda: ["linux", "windows"])
    services: list[str] = Field(default_factory=lambda: ["http", "dns", "tls"])
    roles: list[str] = Field(default_factory=lambda: ["perimeter", "internal"])
    exclude_platforms: list[str] = Field(default_factory=list)
    exclude_services: list[str] = Field(default_factory=list)


class EnrichedRule(BaseModel):
    sid: int
    gid: int = 1
    rev: int = 1
    action: str = "alert"
    protocol: str = ""
    src: str = ""
    src_port: str = ""
    direction: str = "->"
    dst: str = ""
    dst_port: str = ""
    msg: str = ""
    classtype: str = ""
    priority: int | None = None
    enabled: bool = True
    raw: str = ""
    reference: list[str] = Field(default_factory=list)
    metadata: dict[str, list[str]] = Field(default_factory=dict)
    cves: list[str] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    severity: str = "unknown"
    created_at: date | None = None
    updated_at: date | None = None
    age_days: int | None = None
    outdated: bool = False
    relevance_score: float = 0.0
    relevance_label: str = "unknown"
    relevance_reasons: list[str] = Field(default_factory=list)
    source_file: str | None = None

    def cve_urls(self) -> list[str]:
        return [f"https://nvd.nist.gov/vuln/detail/{cve}" for cve in self.cves]


class CatalogSummary(BaseModel):
    total_rules: int
    enabled: int
    disabled: int
    with_cve: int
    high_severity: int
    outdated: int
    by_severity: dict[str, int]
    by_relevance: dict[str, int]
    top_platforms: dict[str, int]


class EveAlertView(BaseModel):
    timestamp: str | None = None
    src_ip: str | None = None
    dest_ip: str | None = None
    src_port: int | None = None
    dest_port: int | None = None
    proto: str | None = None
    signature: str | None = None
    signature_id: int | None = None
    category: str | None = None
    severity: int | None = None
    rule: EnrichedRule | None = None
    extras: dict[str, Any] = Field(default_factory=dict)
