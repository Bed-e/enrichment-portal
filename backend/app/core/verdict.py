"""Verdict logic.

M0 has no verdict engine: the rules in docs/verdict-rules.md are proposed and approved in
M1 (design.md D7). Until then a global IP gets a fixed placeholder verdict.
"""

from app.core.models import Classification, SourceResult, Verdict

PLACEHOLDER_RULES_VERSION = "0.0"


def compute_verdict(classification: Classification, results: list[SourceResult]) -> Verdict:
    if not classification.is_global:
        label = classification.category.replace("_", " ").capitalize()
        return Verdict(
            level="not_applicable",
            summary=f"{label} address. External sources were not queried.",
            reasons=[],
            rules_version=PLACEHOLDER_RULES_VERSION,
        )
    if not any(r.status in ("ok", "no_data") for r in results):
        return Verdict(
            level="unknown",
            summary="No source could answer, so nothing can be said about this IP.",
            reasons=[],
            rules_version=PLACEHOLDER_RULES_VERSION,
        )
    return Verdict(
        level="unknown",
        summary="Verdict rules are added in M1.",
        reasons=[],
        rules_version=PLACEHOLDER_RULES_VERSION,
    )
