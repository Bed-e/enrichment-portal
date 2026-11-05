from ipaddress import ip_address

import pytest

from app.core.ip_classify import classify


@pytest.mark.parametrize(
    ("ip", "category"),
    [
        ("0.0.0.0", "unspecified"),
        ("127.0.0.1", "loopback"),
        ("127.5.5.5", "loopback"),
        ("169.254.1.1", "link_local"),
        ("224.0.0.1", "multicast"),
        ("100.64.0.1", "shared"),
        ("100.127.255.254", "shared"),
        ("192.0.2.1", "documentation"),
        ("198.51.100.7", "documentation"),
        ("203.0.113.9", "documentation"),
        ("10.0.0.5", "private"),
        ("172.16.5.5", "private"),
        ("192.168.1.1", "private"),
        ("240.0.0.1", "reserved"),
        ("255.255.255.255", "reserved"),
        ("0.1.2.3", "reserved"),
        ("198.18.0.1", "reserved"),
        ("8.8.8.8", "global"),
        ("1.1.1.1", "global"),
        ("172.32.0.1", "global"),
        # IPv6 is classified too, although the API only accepts IPv4 until M4.
        ("::1", "loopback"),
        ("fe80::1", "link_local"),
        ("fc00::1", "private"),
        ("2001:db8::1", "documentation"),
        ("2606:4700::1111", "global"),
    ],
)
def test_category(ip: str, category: str) -> None:
    assert classify(ip_address(ip)).category == category


def test_global_has_no_explanation() -> None:
    result = classify(ip_address("8.8.8.8"))
    assert result.is_global is True
    assert result.explanation is None


@pytest.mark.parametrize(
    "ip",
    ["0.0.0.0", "127.0.0.1", "169.254.1.1", "224.0.0.1", "100.64.0.1", "192.0.2.1"]
    + ["10.0.0.5", "240.0.0.1"],
)
def test_every_non_global_category_explains_itself(ip: str) -> None:
    result = classify(ip_address(ip))
    assert result.is_global is False
    assert result.explanation
    assert ip in result.explanation
