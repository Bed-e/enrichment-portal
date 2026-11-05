"""Rules 0.2 (docs/verdict-rules.md): the reputation sources. Pure function, no network."""

from ipaddress import ip_address
from typing import Any

import pytest

from app.core.ip_classify import classify
from app.core.models import SourceResult
from app.core.verdict import compute_verdict
from app.sources.abuseipdb import AbuseIPDB
from app.sources.virustotal import VirusTotal
from tests.conftest import load_fixture

GLOBAL = classify(ip_address("8.8.8.8"))


def make(name: str, display: str, status: str = "ok", **summary: Any) -> SourceResult:
    return SourceResult(
        name=name,
        display_name=display,
        status=status,  # type: ignore[arg-type]
        summary=summary if status == "ok" else None,
        error=None if status in ("ok", "no_data") else "failed",
    )


def internetdb(status: str = "ok", tags: list[str] | None = None) -> SourceResult:
    return make(
        "shodan_internetdb", "Shodan InternetDB", status, tags=tags or [], vulns=[], open_ports=[]
    )


def abuse(status: str = "ok", score: Any = 0, tor: bool = False, white: bool = False):
    return make(
        "abuseipdb",
        "AbuseIPDB",
        status,
        abuse_confidence_score=score,
        total_reports=5,
        is_tor=tor,
        is_whitelisted=white,
    )


def greynoise(status: str = "ok", cls: str | None = None, noise: bool = False, riot: bool = False):
    return make(
        "greynoise", "GreyNoise Community", status, classification=cls, noise=noise, riot=riot
    )


def vt(status: str = "ok", malicious: Any = 0) -> SourceResult:
    return make("virustotal", "VirusTotal", status, malicious=malicious, suspicious=0)


def context() -> list[SourceResult]:
    return [make("rdap", "RDAP"), make("team_cymru", "Team Cymru IP to ASN")]


def verdict(*results: SourceResult):
    return compute_verdict(GLOBAL, [*results, *context()])


def test_rules_version_is_0_2() -> None:
    assert verdict(internetdb()).rules_version == "0.2"


# S5 to S7: AbuseIPDB score bands
@pytest.mark.parametrize(
    ("score", "weight"),
    [(1, "low"), (24, "low"), (25, "medium"), (74, "medium"), (75, "high"), (100, "high")],
)
def test_abuseipdb_score_bands(score: int, weight: str) -> None:
    result = verdict(internetdb(), abuse(score=score))
    assert [(r.signal, r.weight) for r in result.reasons] == [
        (f"AbuseIPDB confidence score {score}/100", weight)
    ]
    assert (
        result.level == {"high": "malicious", "medium": "suspicious", "low": "no_known_bad"}[weight]
    )


@pytest.mark.parametrize("score", [0, None, "90", True])
def test_abuseipdb_zero_or_odd_scores_fire_nothing(score: Any) -> None:
    assert verdict(internetdb(), abuse(score=score)).reasons == []


def test_abuseipdb_tor_is_medium() -> None:  # S8
    result = verdict(internetdb(), abuse(tor=True))
    assert result.level == "suspicious"
    assert [(r.signal, r.weight) for r in result.reasons] == [
        ("AbuseIPDB: Tor exit node", "medium")
    ]


# S9 to S11: VirusTotal malicious-vendor bands
@pytest.mark.parametrize(
    ("count", "weight"),
    [(1, "low"), (2, "low"), (3, "medium"), (9, "medium"), (10, "high"), (60, "high")],
)
def test_virustotal_bands(count: int, weight: str) -> None:
    result = verdict(internetdb(), vt(malicious=count))
    assert [r.weight for r in result.reasons] == [weight]
    assert result.reasons[0].source == "virustotal"


def test_virustotal_wording_is_singular_for_one_vendor() -> None:
    assert verdict(internetdb(), vt(malicious=1)).reasons[0].signal == (
        "VirusTotal: 1 vendor flags it as malicious"
    )
    assert verdict(internetdb(), vt(malicious=5)).reasons[0].signal == (
        "VirusTotal: 5 vendors flag it as malicious"
    )


def test_virustotal_zero_fires_nothing() -> None:
    assert verdict(internetdb(), vt(malicious=0)).reasons == []


# S12, S13: GreyNoise
def test_greynoise_malicious_is_high() -> None:
    result = verdict(internetdb(), greynoise(cls="malicious", noise=True))
    assert result.level == "malicious"
    assert result.summary.startswith("Flagged by: GreyNoise classification: malicious.")


def test_greynoise_noise_alone_is_low_and_does_not_raise_the_level() -> None:
    result = verdict(internetdb(), greynoise(cls="unknown", noise=True))
    assert result.level == "no_known_bad"
    assert [(r.signal, r.weight) for r in result.reasons] == [
        ("GreyNoise: seen scanning the internet", "low")
    ]


def test_greynoise_benign_noise_fires_nothing() -> None:
    assert verdict(internetdb(), greynoise(cls="benign", noise=True, riot=True)).reasons == []


# Known-benign information is a note, never a signal and never a level change
def test_benign_information_is_a_note_not_a_signal() -> None:
    result = verdict(internetdb(), greynoise(cls="benign", riot=True), abuse(white=True))
    assert result.level == "no_known_bad"
    assert result.reasons == []
    assert "GreyNoise lists it as a known benign service." in result.summary
    assert "AbuseIPDB lists it as whitelisted." in result.summary


def test_benign_note_does_not_lower_a_flagged_verdict() -> None:
    result = verdict(internetdb(), vt(malicious=12), greynoise(cls="benign", riot=True))
    assert result.level == "malicious"  # a benign listing never hides a real detection
    assert "known benign service" in result.summary


# Levels
def test_independent_medium_signals_from_different_sources_stay_suspicious() -> None:
    result = verdict(internetdb(), abuse(score=40), vt(malicious=5))
    assert result.level == "suspicious"
    assert [r.weight for r in result.reasons] == ["medium", "medium"]
    assert {r.source for r in result.reasons} == {"abuseipdb", "virustotal"}


def test_reasons_are_ordered_high_then_medium_then_low_across_sources() -> None:
    result = verdict(
        internetdb(tags=["honeypot"]), abuse(score=90), vt(malicious=2), greynoise(cls="malicious")
    )
    assert [r.weight for r in result.reasons] == ["high", "high", "low", "low"]
    assert result.level == "malicious"


# L3, generalised
def test_l3_unknown_only_when_no_flagging_source_answered() -> None:
    result = verdict(
        internetdb("timeout"),
        abuse("error"),
        greynoise("rate_limited"),
        vt("not_configured"),
    )
    assert result.level == "unknown"
    assert "None of the sources that can flag an IP" in result.summary
    for name in ("Shodan InternetDB", "AbuseIPDB", "GreyNoise Community", "VirusTotal"):
        assert name in result.summary
    assert "Not answered:" in result.summary


def test_flagging_source_with_no_data_counts_as_having_looked() -> None:
    result = verdict(internetdb("timeout"), abuse("no_data"), greynoise("no_data"), vt("no_data"))
    assert result.level == "no_known_bad"


def test_internetdb_down_but_a_reputation_source_answered_is_not_unknown() -> None:
    result = verdict(internetdb("timeout"), abuse(score=0))
    assert result.level == "no_known_bad"
    assert result.summary.startswith("No red flags found by AbuseIPDB.")
    assert "Shodan InternetDB (timeout)" in result.summary  # and the gap is named


# Summary wording
def test_weak_evidence_wording_only_while_just_internetdb_answered() -> None:
    only_exposure = verdict(internetdb(), abuse("not_configured"), vt("not_configured"))
    assert "weak evidence" in only_exposure.summary
    with_reputation = verdict(internetdb(), abuse(score=0))
    assert "weak evidence" not in with_reputation.summary
    assert with_reputation.summary.startswith("No red flags found by Shodan InternetDB, AbuseIPDB.")


def test_not_configured_sources_are_named_and_never_make_it_cleaner() -> None:
    result = verdict(internetdb(), abuse("not_configured"), greynoise("not_configured"))
    assert result.level == "no_known_bad"
    assert "AbuseIPDB (not configured)" in result.summary
    assert "GreyNoise Community (not configured)" in result.summary


def test_a_failed_reputation_source_never_hides_a_flag_from_another() -> None:
    result = verdict(internetdb(), abuse("timeout"), vt(malicious=20))
    assert result.level == "malicious"
    assert result.summary.endswith("Not answered: AbuseIPDB (timeout).")


# The real recorded data for 8.8.8.8 (design.md D13): the case that set the thresholds.
def test_recorded_8_8_8_8_is_no_known_bad_not_suspicious() -> None:
    abuse_data = load_fixture("abuseipdb", "ok_8_8_8_8")["body"]["data"]
    vt_attrs = load_fixture("virustotal", "ok_8_8_8_8")["body"]["data"]["attributes"]
    results = [
        make("shodan_internetdb", "Shodan InternetDB", tags=["pqc"], vulns=[], open_ports=[53]),
        make("abuseipdb", "AbuseIPDB", **AbuseIPDB._summarize(abuse_data)),
        make("greynoise", "GreyNoise Community", "no_data"),
        make("virustotal", "VirusTotal", **VirusTotal._summarize(vt_attrs)),
        make("ipinfo", "ipinfo Lite", asn="AS15169"),
        *context(),
    ]
    result = compute_verdict(GLOBAL, results)
    assert result.level == "no_known_bad"  # one vendor in ~92 must not make Google DNS suspicious
    assert [(r.source, r.weight) for r in result.reasons] == [("virustotal", "low")]
    assert "AbuseIPDB lists it as whitelisted." in result.summary
    assert "Not answered" not in result.summary


def test_a_fresh_clone_with_no_keys_gets_the_0_1_behaviour() -> None:
    result = verdict(
        internetdb(),
        make("abuseipdb", "AbuseIPDB", "not_configured"),
        make("greynoise", "GreyNoise Community", "not_configured"),
        make("virustotal", "VirusTotal", "not_configured"),
        make("ipinfo", "ipinfo Lite", "not_configured"),
    )
    assert result.level == "no_known_bad"
    assert result.summary.startswith(
        "No red flags found. Only context sources were checked, not reputation sources"
    )
