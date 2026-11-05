"""Pydantic models that define the API contract (design.md section 3)."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel

SourceStatus = Literal[
    "ok", "no_data", "timeout", "rate_limited", "error", "not_configured", "skipped"
]
VerdictLevel = Literal["malicious", "suspicious", "no_known_bad", "unknown", "not_applicable"]
Category = Literal[
    "global",
    "private",
    "loopback",
    "link_local",
    "shared",
    "multicast",
    "reserved",
    "unspecified",
    "documentation",
]


class SourceResult(BaseModel):
    name: str
    display_name: str
    status: SourceStatus
    latency_ms: int | None = None
    summary: dict[str, Any] | None = None
    raw: Any | None = None
    error: str | None = None


class Classification(BaseModel):
    category: Category
    is_global: bool
    explanation: str | None = None


class Reason(BaseModel):
    source: str
    signal: str
    weight: Literal["high", "medium", "low"]


class Verdict(BaseModel):
    level: VerdictLevel
    summary: str
    reasons: list[Reason] = []
    rules_version: str


class LookupResponse(BaseModel):
    lookup_id: int | None = None
    ip: str
    ip_version: Literal[4, 6]
    queried_at: datetime
    classification: Classification
    verdict: Verdict
    sources: list[SourceResult]
