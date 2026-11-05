"""Classify an IP address as global, private, reserved and so on."""

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_network

from app.core.models import Category, Classification

IP = IPv4Address | IPv6Address

_SHARED = IPv4Network("100.64.0.0/10")
_PRIVATE = [IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
_PRIVATE_V6 = IPv6Network("fc00::/7")
_DOCUMENTATION = [
    ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
]

_EXPLANATIONS: dict[str, str] = {
    "private": (
        "{ip} is a private address (RFC 1918 or IPv6 ULA). It is not routable on the public "
        "internet, so public threat-intel sources have no data on it. If it appeared in an "
        "alert, the activity originated inside your network or behind NAT/VPN; investigate "
        "with internal tools such as DHCP logs, asset inventory and EDR."
    ),
    "loopback": (
        "{ip} is a loopback address. It always refers to the machine that generated the "
        "traffic, so it says nothing about any external host. Look at the local host itself."
    ),
    "link_local": (
        "{ip} is a link-local address. It is only valid on a single network segment and is "
        "never routed. Traffic from it came from a device on the same local link."
    ),
    "shared": (
        "{ip} is in the shared address space (100.64.0.0/10, RFC 6598) used by carrier-grade "
        "NAT. It is not globally unique, so public sources cannot tell you who used it. Ask "
        "the ISP or check your own NAT logs."
    ),
    "multicast": (
        "{ip} is a multicast address. It addresses a group of hosts rather than one host, "
        "so it cannot be attributed to an owner or a reputation."
    ),
    "reserved": (
        "{ip} is in a reserved range (for example 240.0.0.0/4, 0.0.0.0/8, benchmarking or "
        "broadcast). It is not valid for normal public use, so traffic from it is spoofed, "
        "misconfigured or part of a test."
    ),
    "unspecified": (
        "{ip} is the unspecified address. It means no address and is never a real source "
        "or destination."
    ),
    "documentation": (
        "{ip} is reserved for documentation and examples (RFC 5737 or RFC 3849). It should "
        "never appear on a real network, so seeing it in an alert suggests a copied example "
        "or spoofed traffic."
    ),
}


def _category(ip: IP) -> Category:
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.is_multicast:
        return "multicast"
    if ip.version == 4 and ip in _SHARED:
        return "shared"
    if any(ip in net for net in _DOCUMENTATION if net.version == ip.version):
        return "documentation"
    if ip.version == 4 and any(ip in net for net in _PRIVATE):
        return "private"
    if ip.version == 6 and ip in _PRIVATE_V6:
        return "private"
    if not ip.is_global:
        return "reserved"
    return "global"


def classify(ip: IP) -> Classification:
    category = _category(ip)
    if category == "global":
        return Classification(category="global", is_global=True, explanation=None)
    return Classification(
        category=category,
        is_global=False,
        explanation=_EXPLANATIONS[category].format(ip=ip),
    )
