"""Host features: DNS records, TLS certificate and domain age (RDAP/WHOIS).

These need the network (tens of milliseconds to a few seconds), so they only
run in "full" scans, each with a hard timeout, and in parallel so the slowest
lookup sets the latency rather than the sum of all three.

WHY they are not model inputs: the training URLs are from 2020 and most of
those domains have expired or changed hands, so we cannot know what their DNS
or WHOIS looked like back then. They feed the hand-written rules instead.
"""
from __future__ import annotations

import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import dns.exception
import dns.resolver
import httpx

from .netguard import BlockedAddress, is_public_ip, resolve_public
from .parsing import ParsedURL


def dns_records(host: str, registrable: str, budget: float = 2.5) -> dict:
    """A/AAAA for the host, MX/NS for the registrable domain, plus lowest TTL.

    All four queries share one time budget so a slow resolver cannot stall
    the scan for 4 x timeout.
    """
    resolver = dns.resolver.Resolver()
    deadline = time.monotonic() + budget
    out: dict = {"resolves": False, "a": [], "aaaa_count": 0, "mx_count": 0,
                 "ns_count": 0, "min_ttl": None, "error": None}
    for name, rtype in ((host, "A"), (host, "AAAA"), (registrable, "MX"), (registrable, "NS")):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            out["error"] = out["error"] or "timeout"
            break
        try:
            answer = resolver.resolve(name, rtype, lifetime=remaining)
        except dns.resolver.NXDOMAIN:
            if rtype == "A":
                out["error"] = "NXDOMAIN"  # the name does not exist at all
                break
            continue
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            continue
        except dns.exception.Timeout:
            out["error"] = "timeout"
            break
        ttl = answer.rrset.ttl if answer.rrset is not None else None
        if ttl is not None:
            out["min_ttl"] = ttl if out["min_ttl"] is None else min(out["min_ttl"], ttl)
        if rtype == "A":
            out["a"] = sorted(r.address for r in answer)[:8]
        elif rtype == "AAAA":
            out["aaaa_count"] = len(answer)
        elif rtype == "MX":
            out["mx_count"] = len(answer)
        else:
            out["ns_count"] = len(answer)
    out["resolves"] = bool(out["a"] or out["aaaa_count"])
    return out


def _cert_time(value: str) -> datetime:
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), tz=timezone.utc)


def tls_certificate(host: str, ip: str, port: int = 443, timeout: float = 3.0) -> dict:
    """Handshake with the exact IP we validated and read the certificate.

    Connecting to `ip` (not `host`) means DNS rebinding cannot swap in a
    private address between the SSRF check and the connection; server_hostname
    still sends SNI and checks the certificate against the real host name.
    """
    out: dict = {"https": False, "valid": False, "error": None, "issuer": None,
                 "subject": None, "not_before": None, "not_after": None,
                 "age_days": None, "days_left": None, "san_count": 0, "version": None}
    if not is_public_ip(ip):
        out["error"] = "blocked: non-public address"
        return out
    context = ssl.create_default_context()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                out["version"] = tls.version()
    except ssl.SSLCertVerificationError as exc:
        out.update(https=True, error=exc.verify_message or str(exc))
        return out
    except (OSError, ssl.SSLError) as exc:
        out["error"] = f"no TLS on port {port}: {exc.__class__.__name__}"
        return out

    now = datetime.now(timezone.utc)
    issuer = dict(item[0] for item in cert.get("issuer", ()))
    subject = dict(item[0] for item in cert.get("subject", ()))
    not_before, not_after = _cert_time(cert["notBefore"]), _cert_time(cert["notAfter"])
    out.update(
        https=True, valid=True,
        issuer=issuer.get("organizationName") or issuer.get("commonName"),
        subject=subject.get("commonName"),
        not_before=not_before.isoformat(), not_after=not_after.isoformat(),
        age_days=(now - not_before).days, days_left=(not_after - now).days,
        san_count=len(cert.get("subjectAltName", ())),
    )
    return out


def _parse_date(value) -> datetime | None:
    if isinstance(value, list):
        value = min((v for v in value if v), default=None)  # WHOIS often returns several
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _rdap(domain: str, timeout: float) -> dict | None:
    """RDAP is WHOIS's JSON successor; ICANN made it the required protocol for
    gTLDs in January 2025. rdap.org redirects to the right registry server."""
    resp = httpx.get(f"https://rdap.org/domain/{domain}", timeout=timeout,
                     follow_redirects=True, headers={"Accept": "application/rdap+json"})
    if resp.status_code != 200:
        return None
    data = resp.json()
    created = next((e.get("eventDate") for e in data.get("events", [])
                    if e.get("eventAction") == "registration"), None)
    registrar = None
    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            for item in (entity.get("vcardArray") or [None, []])[1]:
                if item and item[0] == "fn":
                    registrar = item[3]
    return {"created": _parse_date(created), "registrar": registrar, "source": "rdap"}


def _whois(domain: str, timeout: float) -> dict | None:
    """Classic port-43 WHOIS, still the only option for many country TLDs."""
    import whois  # imported lazily: only needed when RDAP has no answer

    record = whois.whois(domain, timeout=max(1, int(timeout)), quiet=True)
    created = _parse_date(record.get("creation_date"))
    registrar = record.get("registrar")
    if isinstance(registrar, list):
        registrar = registrar[0] if registrar else None
    return {"created": created, "registrar": registrar, "source": "whois"}


def domain_age(domain: str, timeout: float = 4.0) -> dict:
    """Days since the domain was registered: RDAP first, WHOIS as fallback."""
    out: dict = {"created": None, "age_days": None, "registrar": None, "source": None, "error": None}
    info = None
    for lookup in (_rdap, _whois):
        try:
            info = lookup(domain, timeout)
        except Exception as exc:  # network errors, odd WHOIS formats: never fatal
            out["error"] = f"{lookup.__name__.strip('_')}: {exc.__class__.__name__}"
            continue
        if info and info.get("created"):
            break
    if info and info.get("created"):
        created = info["created"]
        out.update(created=created.isoformat(), registrar=info.get("registrar"),
                   source=info["source"], error=None,
                   age_days=(datetime.now(timezone.utc) - created).days)
    elif out["error"] is None:
        out["error"] = "no registration date published"
    return out


def gather_host_intel(parsed: ParsedURL) -> dict:
    """Run DNS, TLS and domain-age lookups in parallel; never raises."""
    try:
        ips = resolve_public(parsed.host, parsed.port or 443)
    except BlockedAddress as exc:
        return {"blocked": str(exc), "dns": None, "tls": None, "whois": None}

    with ThreadPoolExecutor(max_workers=3) as pool:
        dns_f = None if parsed.is_ip else pool.submit(dns_records, parsed.host, parsed.registrable_domain)
        tls_f = pool.submit(tls_certificate, parsed.host, ips[0], 443)
        age_f = None if parsed.is_ip else pool.submit(domain_age, parsed.registrable_domain)
        return {
            "blocked": None,
            "dns": dns_f.result() if dns_f else None,
            "tls": tls_f.result(),
            "whois": age_f.result() if age_f else None,
        }
