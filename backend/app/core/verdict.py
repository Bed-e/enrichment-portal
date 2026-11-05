"""The verdict engine: a pure function of the classification and the source results.

The rules are written down, with their reasoning, in docs/verdict-rules.md (design.md D7).
Keep the two in step: change the document first, then the code, and bump RULES_VERSION.
"""

from typing import Literal

from app.core.models import Classification, Reason, SourceResult, Verdict, VerdictLevel

RULES_VERSION = "0.1"

# The only M1 source that can raise a red flag. RDAP and Team Cymru describe ownership and
# routing, so they produce no signals (docs/verdict-rules.md, "What the three M1 sources...").
FLAGGING_SOURCE = "shodan_internetdb"

# Shodan documents InternetDB's fields but not its tag values, so these names are unconfirmed
# (design.md section 4). Compared case-insensitively; any other tag is ignored.
HIGH_TAGS = ("c2", "malware", "compromised", "doublepulsar")
MEDIUM_TAGS = ("tor", "onion", "vpn", "proxy")
LOW_TAGS = ("honeypot",)

NO_SOURCE_SUMMARY = "No source could answer, so nothing can be said about this IP."
FLAGGER_MISSING_SUMMARY = (
    "Shodan InternetDB, the only source that can flag an IP, did not answer, "
    "so nothing can be said about this IP."
)
NO_KNOWN_BAD_SUMMARY = (
    "No red flags found. Only context sources were checked, not reputation sources, "
    "so this is weak evidence."
)


def compute_verdict(classification: Classification, results: list[SourceResult]) -> Verdict:
    if not classification.is_global:  # L1
        label = classification.category.replace("_", " ").capitalize()
        return _verdict(
            "not_applicable", f"{label} address. External sources were not queried.", []
        )

    answered = [r for r in results if r.status in ("ok", "no_data")]
    if not answered:  # L2: every source failed, so there is nothing to add to the summary
        return _verdict("unknown", NO_SOURCE_SUMMARY, [])

    coverage = _coverage_note(results)
    flagger = next((r for r in results if r.name == FLAGGING_SOURCE), None)
    if flagger is None or flagger.status not in ("ok", "no_data"):  # L3
        return _verdict("unknown", f"{FLAGGER_MISSING_SUMMARY}{coverage}", [])

    reasons = _signals(flagger)
    high = [r.signal for r in reasons if r.weight == "high"]
    medium = [r.signal for r in reasons if r.weight == "medium"]
    if high:  # L4
        return _verdict("malicious", f"Flagged by: {'; '.join(high)}.{coverage}", reasons)
    if medium:  # L5
        return _verdict(
            "suspicious", f"Worth a closer look: {'; '.join(medium)}.{coverage}", reasons
        )
    return _verdict("no_known_bad", f"{NO_KNOWN_BAD_SUMMARY}{coverage}", reasons)  # L6


def _verdict(level: VerdictLevel, summary: str, reasons: list[Reason]) -> Verdict:
    return Verdict(level=level, summary=summary, reasons=reasons, rules_version=RULES_VERSION)


def _signals(result: SourceResult) -> list[Reason]:
    """S1 to S4. Empty unless InternetDB returned data; high first, then medium, then low."""
    if result.status != "ok" or not result.summary:
        return []
    tags = [str(t).lower() for t in result.summary.get("tags") or []]
    vulns = result.summary.get("vulns") or []
    reasons: list[Reason] = []
    for weight, wanted in (("high", HIGH_TAGS), ("medium", MEDIUM_TAGS)):
        reasons += [_tag_reason(result, tag, weight) for tag in tags if tag in wanted]
    if vulns:
        reasons.append(
            Reason(
                source=result.name,
                signal=f"Exposed to {len(vulns)} known CVE(s)",
                weight="low",
            )
        )
    reasons += [_tag_reason(result, tag, "low") for tag in tags if tag in LOW_TAGS]
    return reasons


def _tag_reason(result: SourceResult, tag: str, weight: Literal["high", "medium", "low"]) -> Reason:
    return Reason(source=result.name, signal=f"Shodan tag: {tag}", weight=weight)


def _coverage_note(results: list[SourceResult]) -> str:
    """ "A sentence naming sources that did not answer, or "". Missing evidence is said out loud."""
    missing = [
        f"{r.display_name} ({r.status.replace('_', ' ')})"
        for r in results
        if r.status not in ("ok", "no_data")
    ]
    return f" Not answered: {', '.join(missing)}." if missing else ""
