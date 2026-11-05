"""One test per rule in docs/verdict-rules.md. Pure function, so no network or mocks."""

from ipaddress import ip_address
from typing import Any

import pytest

from app.core.ip_classify import classify
from app.core.models import SourceResult
from app.core.verdict import RULES_VERSION, compute_verdict

GLOBAL = classify(ip_address("8.8.8.8"))


def internetdb(tags: list[str] | None = None, vulns: list[str] | None = None) -> SourceResult:
    summary: dict[str, Any] = {
        "open_ports": [],
        "tags": tags or [],
        "vulns": vulns or [],
        "hostnames": [],
        "cpes": [],
    }
    return SourceResult(
        name="shodan_internetdb", display_name="Shodan InternetDB", status="ok", summary=summary
    )


def source(name: str, display: str, status: str) -> SourceResult:
    return SourceResult(
        name=name,
        display_name=display,
        status=status,  # type: ignore[arg-type]
        summary={} if status == "ok" else None,
        error=None if status in ("ok", "no_data") else "failed",
    )


def rdap(status: str = "ok") -> SourceResult:
    return source("rdap", "RDAP", status)


def cymru(status: str = "ok") -> SourceResult:
    return source("team_cymru", "Team Cymru IP to ASN", status)


def verdict(*results: SourceResult):
    return compute_verdict(GLOBAL, list(results))


def test_rules_version() -> None:
    assert verdict(internetdb(), rdap(), cymru()).rules_version == RULES_VERSION == "0.1"


# L1
@pytest.mark.parametrize("ip", ["10.0.0.5", "127.0.0.1", "169.254.1.1", "192.0.2.1", "224.0.0.1"])
def test_l1_private_and_reserved_addresses_are_not_applicable(ip: str) -> None:
    skipped = [source("shodan_internetdb", "Shodan InternetDB", "skipped")]
    result = compute_verdict(classify(ip_address(ip)), skipped)
    assert result.level == "not_applicable"
    assert "External sources were not queried" in result.summary
    assert result.reasons == []


# L2
def test_l2_no_source_answered_is_unknown() -> None:
    result = verdict(internetdb_failed("timeout"), rdap("timeout"), cymru("error"))
    assert result.level == "unknown"
    assert result.summary == "No source could answer, so nothing can be said about this IP."
    assert result.reasons == []


def test_l2_applies_to_every_kind_of_missing_evidence() -> None:
    failures = [
        source("shodan_internetdb", "Shodan InternetDB", "rate_limited"),
        source("rdap", "RDAP", "not_configured"),
        source("team_cymru", "Team Cymru IP to ASN", "error"),
    ]
    assert compute_verdict(GLOBAL, failures).level == "unknown"


def internetdb_failed(status: str) -> SourceResult:
    return source("shodan_internetdb", "Shodan InternetDB", status)


# L3
@pytest.mark.parametrize("status", ["timeout", "error", "rate_limited", "not_configured"])
def test_l3_flagging_source_missing_is_unknown_even_if_others_answer(status: str) -> None:
    result = verdict(internetdb_failed(status), rdap(), cymru())
    assert result.level == "unknown"
    assert "only source that can flag an IP" in result.summary
    assert f"Shodan InternetDB ({status.replace('_', ' ')})" in result.summary
    assert result.reasons == []


def test_l3_flagging_source_not_registered_at_all_is_unknown() -> None:
    assert verdict(rdap(), cymru()).level == "unknown"


# L4 / S1
@pytest.mark.parametrize("tag", ["c2", "malware", "compromised", "doublepulsar"])
def test_l4_high_tag_is_malicious(tag: str) -> None:
    result = verdict(internetdb(tags=[tag]), rdap(), cymru())
    assert result.level == "malicious"
    assert result.summary == f"Flagged by: Shodan tag: {tag}."
    assert [r.model_dump() for r in result.reasons] == [
        {"source": "shodan_internetdb", "signal": f"Shodan tag: {tag}", "weight": "high"}
    ]


def test_tags_are_matched_case_insensitively() -> None:
    assert verdict(internetdb(tags=["C2"]), rdap(), cymru()).level == "malicious"


def test_high_beats_medium() -> None:
    result = verdict(internetdb(tags=["tor", "c2"]), rdap(), cymru())
    assert result.level == "malicious"
    assert [r.weight for r in result.reasons] == ["high", "medium"]  # high listed first


# L5 / S2
@pytest.mark.parametrize("tag", ["tor", "onion", "vpn", "proxy"])
def test_l5_medium_tag_is_suspicious(tag: str) -> None:
    result = verdict(internetdb(tags=[tag]), rdap("no_data"), cymru())
    assert result.level == "suspicious"
    assert result.summary == f"Worth a closer look: Shodan tag: {tag}."
    assert [r.weight for r in result.reasons] == ["medium"]


def test_several_medium_signals_stay_suspicious() -> None:
    result = verdict(internetdb(tags=["vpn", "proxy", "tor"]), rdap(), cymru())
    assert result.level == "suspicious"
    assert [r.weight for r in result.reasons] == ["medium"] * 3


# L6 and S3 / S4
def test_l6_nothing_fired_is_no_known_bad_with_the_weak_evidence_wording() -> None:
    result = verdict(internetdb(), rdap(), cymru())
    assert result.level == "no_known_bad"
    assert result.summary == (
        "No red flags found. Only context sources were checked, not reputation sources, "
        "so this is weak evidence."
    )
    assert result.reasons == []


def test_unlisted_tags_are_ignored() -> None:
    result = verdict(internetdb(tags=["cloud", "cdn", "pqc"]), rdap(), cymru())
    assert result.level == "no_known_bad"
    assert result.reasons == []


def test_s3_cves_are_low_and_never_raise_the_level() -> None:
    cves = [f"CVE-2020-{n}" for n in range(1000, 1012)]  # even a dozen stays low
    result = verdict(internetdb(vulns=cves), rdap(), cymru())
    assert result.level == "no_known_bad"
    assert [r.model_dump() for r in result.reasons] == [
        {"source": "shodan_internetdb", "signal": "Exposed to 12 known CVE(s)", "weight": "low"}
    ]


def test_s4_honeypot_is_low_and_never_raises_the_level() -> None:
    result = verdict(internetdb(tags=["honeypot"]), rdap(), cymru())
    assert result.level == "no_known_bad"
    assert [r.weight for r in result.reasons] == ["low"]


def test_low_signals_are_listed_but_do_not_change_a_higher_level() -> None:
    result = verdict(internetdb(tags=["vpn", "honeypot"], vulns=["CVE-2020-1"]), rdap(), cymru())
    assert result.level == "suspicious"
    assert [r.weight for r in result.reasons] == ["medium", "low", "low"]


def test_internetdb_no_data_with_other_sources_is_no_known_bad() -> None:
    result = verdict(internetdb_failed("no_data"), rdap(), cymru())
    assert result.level == "no_known_bad"


# Coverage note
def test_missing_sources_are_named_and_never_make_the_verdict_cleaner() -> None:
    result = verdict(internetdb(), rdap("timeout"), cymru("rate_limited"))
    assert result.level == "no_known_bad"
    assert result.summary.endswith(
        " Not answered: RDAP (timeout), Team Cymru IP to ASN (rate limited)."
    )


def test_coverage_note_also_follows_a_malicious_verdict() -> None:
    result = verdict(internetdb(tags=["c2"]), rdap("error"), cymru())
    assert result.level == "malicious"
    assert result.summary == "Flagged by: Shodan tag: c2. Not answered: RDAP (error)."


def test_no_coverage_note_when_every_source_answered() -> None:
    assert "Not answered" not in verdict(internetdb(), rdap(), cymru("no_data")).summary
