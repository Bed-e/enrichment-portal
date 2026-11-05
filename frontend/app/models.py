"""The frontend's own copy of the response contract (design.md section 3).

It deliberately does not import backend code: the contract is the only link (D2).
"""

from typing import Any

from pydantic import BaseModel


class Source(BaseModel):
    name: str
    display_name: str
    status: str
    latency_ms: int | None = None
    summary: dict[str, Any] | None = None
    raw: Any | None = None
    error: str | None = None


class Classification(BaseModel):
    category: str
    is_global: bool
    explanation: str | None = None


class Verdict(BaseModel):
    level: str
    summary: str
    rules_version: str


class LookupResult(BaseModel):
    ip: str
    ip_version: int
    queried_at: str
    classification: Classification
    verdict: Verdict
    sources: list[Source]
