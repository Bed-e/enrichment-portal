"""The verdict engine: a pure function of the classification and the source results.

The rules are written down, with their reasoning, in docs/verdict-rules.md (design.md D7).
Keep the two in step: change the document first, then the code, and bump RULES_VERSION.
"""

from collections.abc import Callable
from typing import Any, Literal

from app.core.models import Classification, Reason, SourceResult, Verdict, VerdictLevel

RULES_VERSION = "0.2"

Weight = Literal["high", "medium", "low"]
WEIGHT_ORDER: tuple[Weight, ...] = ("high", "medium", "low")

# The sources that can raise a red flag. RDAP, Team Cymru and ipinfo describe ownership and
# routing, so they produce no signals (docs/verdict-rules.md, "What each source can tell us").
FLAGGING_SOURCES = ("shodan_internetdb", "abuseipdb", "greynoise", "virustotal")
REPUTATION_SOURCES = ("abuseipdb", "greynoise", "virustotal")  # flagging, and not just exposure
DEFAULT_FLAGGING_NAMES = "Shodan InternetDB, AbuseIPDB, GreyNoise Community and VirusTotal"

# Shodan documents InternetDB's fields but not its tag values, so these names are unconfirmed
# (design.md section 4). Compared case-insensitively; any other tag is ignored.
HIGH_TAGS = ("c2", "malware", "compromised", "doublepulsar")
MEDIUM_TAGS = ("tor", "onion", "vpn", "proxy")
LOW_TAGS = ("honeypot",)

# AbuseIPDB confidence score bands and VirusTotal malicious-vendor bands (rules S5 to S11).
# The VirusTotal bands are deliberately high: 8.8.8.8 has one vendor flagging it.
ABUSE_HIGH, ABUSE_MEDIUM = 75, 25
VT_HIGH, VT_MEDIUM = 10, 3

NO_SOURCE_SUMMARY = "No source could answer, so nothing can be said about this IP."
WEAK_EVIDENCE_SUMMARY = (
    "No red flags found. Only context sources were checked, not reputation sources, "
    "so this is weak evidence."
)


def compute_verdict(classification: Classification, results: list[SourceResult]) -> Verdict:
    if not classification.is_global:  # L1
        label = classification.category.replace("_", " ").capitalize()
        return _verdict(
            "not_applicable", f"{label} address. External sources were not queried.", []
        )

    if not any(_answered(r) for r in results):  # L2: nothing answered, nothing to add
        return _verdict("unknown", NO_SOURCE_SUMMARY, [])

    coverage = _coverage_note(results)
    flaggers = [r for r in results if r.name in FLAGGING_SOURCES]
    if not any(_answered(r) for r in flaggers):  # L3
        names = ", ".join(r.display_name for r in flaggers) or DEFAULT_FLAGGING_NAMES
        summary = (
            f"None of the sources that can flag an IP ({names}) answered, "
            "so nothing can be said about this IP."
        )
        return _verdict("unknown", f"{summary}{coverage}", [])

    reasons = _signals(flaggers)
    high = [r.signal for r in reasons if r.weight == "high"]
    medium = [r.signal for r in reasons if r.weight == "medium"]
    notes = _benign_notes(flaggers)  # information only; never changes the level
    if high:  # L4
        return _verdict("malicious", f"Flagged by: {'; '.join(high)}.{notes}{coverage}", reasons)
    if medium:  # L5
        text = f"Worth a closer look: {'; '.join(medium)}.{notes}{coverage}"
        return _verdict("suspicious", text, reasons)
    return _verdict("no_known_bad", f"{_no_known_bad(flaggers)}{notes}{coverage}", reasons)  # L6


def _verdict(level: VerdictLevel, summary: str, reasons: list[Reason]) -> Verdict:
    return Verdict(level=level, summary=summary, reasons=reasons, rules_version=RULES_VERSION)


def _answered(result: SourceResult) -> bool:
    return result.status in ("ok", "no_data")


def _no_known_bad(flaggers: list[SourceResult]) -> str:
    """The 0.1 'weak evidence' wording until a reputation source has answered."""
    answered = [r for r in flaggers if _answered(r)]
    if not any(r.name in REPUTATION_SOURCES for r in answered):
        return WEAK_EVIDENCE_SUMMARY
    return f"No red flags found by {', '.join(r.display_name for r in answered)}."


def _signals(flaggers: list[SourceResult]) -> list[Reason]:
    """Every signal that fired, high first, then medium, then low (stable within a weight)."""
    found: list[Reason] = []
    for result in flaggers:
        if result.status == "ok" and result.summary:
            found += SIGNALS[result.name](result)
    return [r for weight in WEIGHT_ORDER for r in found if r.weight == weight]


def _reason(result: SourceResult, signal: str, weight: Weight) -> Reason:
    return Reason(source=result.name, signal=signal, weight=weight)


def _internetdb_signals(result: SourceResult) -> list[Reason]:  # S1 to S4
    summary = result.summary or {}
    tags = [str(t).lower() for t in summary.get("tags") or []]
    vulns = summary.get("vulns") or []
    reasons = [_reason(result, f"Shodan tag: {t}", "high") for t in tags if t in HIGH_TAGS]
    reasons += [_reason(result, f"Shodan tag: {t}", "medium") for t in tags if t in MEDIUM_TAGS]
    if vulns:
        reasons.append(_reason(result, f"Exposed to {len(vulns)} known CVE(s)", "low"))
    reasons += [_reason(result, f"Shodan tag: {t}", "low") for t in tags if t in LOW_TAGS]
    return reasons


def _abuseipdb_signals(result: SourceResult) -> list[Reason]:  # S5 to S8
    summary = result.summary or {}
    reasons: list[Reason] = []
    score = _number(summary.get("abuse_confidence_score"))
    if score >= 1:
        weight = _band(score, ABUSE_HIGH, ABUSE_MEDIUM)
        reasons.append(_reason(result, f"AbuseIPDB confidence score {score}/100", weight))
    if summary.get("is_tor") is True:
        reasons.append(_reason(result, "AbuseIPDB: Tor exit node", "medium"))
    return reasons


def _virustotal_signals(result: SourceResult) -> list[Reason]:  # S9 to S11
    count = _number((result.summary or {}).get("malicious"))
    if count < 1:
        return []
    weight = _band(count, VT_HIGH, VT_MEDIUM)
    noun = "vendor flags" if count == 1 else "vendors flag"
    return [_reason(result, f"VirusTotal: {count} {noun} it as malicious", weight)]


def _greynoise_signals(result: SourceResult) -> list[Reason]:  # S12, S13
    summary = result.summary or {}
    classification = str(summary.get("classification") or "").lower()
    if classification == "malicious":
        return [_reason(result, "GreyNoise classification: malicious", "high")]
    if summary.get("noise") is True and classification != "benign":
        return [_reason(result, "GreyNoise: seen scanning the internet", "low")]
    return []


SIGNALS: dict[str, Callable[[SourceResult], list[Reason]]] = {
    "shodan_internetdb": _internetdb_signals,
    "abuseipdb": _abuseipdb_signals,
    "greynoise": _greynoise_signals,
    "virustotal": _virustotal_signals,
}


def _band(value: int, high: int, medium: int) -> Weight:
    """high at or above `high`, medium at or above `medium`, otherwise low."""
    return "high" if value >= high else "medium" if value >= medium else "low"


def _number(value: Any) -> int:
    """A count from a summary field, or 0 if it is missing or not a number."""
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _benign_notes(flaggers: list[SourceResult]) -> str:
    """Known-benign information as sentences. Never a signal and never changes the level."""
    notes = []
    for result in flaggers:
        summary = result.summary or {}
        if result.status != "ok":
            continue
        if result.name == "greynoise" and (
            summary.get("riot") is True or str(summary.get("classification")).lower() == "benign"
        ):
            notes.append("GreyNoise lists it as a known benign service.")
        if result.name == "abuseipdb" and summary.get("is_whitelisted") is True:
            notes.append("AbuseIPDB lists it as whitelisted.")
    return f" {' '.join(notes)}" if notes else ""


def _coverage_note(results: list[SourceResult]) -> str:
    """A sentence naming sources that did not answer, or "". Missing evidence is said out loud."""
    missing = [
        f"{r.display_name} ({r.status.replace('_', ' ')})" for r in results if not _answered(r)
    ]
    return f" Not answered: {', '.join(missing)}." if missing else ""
