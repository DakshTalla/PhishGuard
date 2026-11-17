"""SSRF guard: a scan must never make the server talk to a private address.

The API fetches URLs that strangers type in. Without this check, scanning
http://169.254.169.254/ (cloud metadata) or http://localhost:8000/admin would
make *our server* read internal pages on the attacker's behalf. This is called
Server-Side Request Forgery (SSRF), and it is in the OWASP Top 10 (A10:2021).
"""
from __future__ import annotations

import ipaddress
import socket


class BlockedAddress(Exception):
    """The host resolves to an address we refuse to contact."""


def is_public_ip(ip: str) -> bool:
    """True only for globally routable unicast addresses.

    ipaddress.is_global is False for private (10/8, 192.168/16, ...),
    loopback, link-local (169.254/16, the metadata range), carrier-grade NAT
    (100.64/10) and reserved ranges, which is exactly the block list we need.
    """
    addr = ipaddress.ip_address(ip.split("%", 1)[0])  # drop IPv6 zone ids
    if addr.version == 6 and addr.ipv4_mapped:         # ::ffff:127.0.0.1
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


def resolve_public(host: str, port: int = 443) -> list[str]:
    """Resolve `host` and return its addresses, or raise BlockedAddress.

    Refuses the host if ANY address is non-public, because the OS may pick
    any of them when connecting.

    Known limit (documented in the study guide): DNS rebinding. httpx resolves
    the name again when it connects, so a malicious DNS server could answer
    with a public IP here and a private one a moment later. The TLS check in
    host.py avoids this by connecting to the exact IP we validated.
    """
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise BlockedAddress(f"{host} does not resolve") from exc
    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise BlockedAddress(f"{host} does not resolve")
    for ip in ips:
        if not is_public_ip(ip):
            raise BlockedAddress(f"{host} resolves to a non-public address ({ip})")
    return ips
