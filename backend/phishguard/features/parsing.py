"""Normalise a user-supplied URL and split it into named parts.

Every other module works on a ParsedURL, so the training script and the live
API see URLs in exactly the same shape. (If training normalised URLs one way
and serving another, the model would quietly get worse: train/serve skew.)
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import tldextract

# WHY suffix_list_urls=(): tldextract normally downloads the latest Public
# Suffix List on first use. The snapshot bundled with the package keeps
# training and serving deterministic and lets the API start offline.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

# Schemes that can run code or read local files are refused outright.
_DANGEROUS_SCHEME = re.compile(r"^(javascript|data|vbscript|file|blob|about|mailto):", re.I)
_HAS_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)
# A host whose last label is all digits (or hex) is an IP in some notation:
# browsers accept http://3232235777/ and http://0xC0A80001/ as 192.168.0.1.
_NUMERIC_LABEL = re.compile(r"^(0x[0-9a-f]+|\d+)$")


class InvalidURL(ValueError):
    """Raised for input we refuse to scan (empty, wrong scheme, no host)."""


@dataclass(frozen=True)
class ParsedURL:
    url: str            # normalised URL that every feature is computed from
    scheme: str         # "http" or "https"
    host: str           # ASCII (punycode) host, lower case, no trailing dot
    unicode_host: str   # how a human sees it, e.g. "аpple.com" with a Cyrillic "а"
    port: int | None    # only when written explicitly in the URL
    path: str
    query: str
    subdomain: str      # "mail.login" in mail.login.example.co.uk
    domain: str         # "example"
    suffix: str         # "co.uk" (the public suffix, roughly "the TLD")
    is_ip: bool
    has_userinfo: bool  # "user@" before the host: http://paypal.com@evil.com/

    @property
    def registrable_domain(self) -> str:
        """example.co.uk: the part someone actually buys from a registrar."""
        if self.is_ip or not self.suffix:
            return self.host
        return f"{self.domain}.{self.suffix}"

    @property
    def tld(self) -> str:
        """Last label only ("uk" for example.co.uk), used for the abused-TLD list."""
        return self.suffix.rsplit(".", 1)[-1] if self.suffix else ""


def _to_ascii(host: str) -> str:
    """Punycode-encode an internationalised host (IDNA), label by label."""
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidURL(f"host is not a valid internationalised domain: {host!r}") from exc


def _to_unicode(host: str) -> str:
    """Decode xn-- labels so humans (and the homoglyph check) see the real letters."""
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except UnicodeError:
                pass  # malformed punycode: keep it as-is, still suspicious
        labels.append(label)
    return ".".join(labels)


def _looks_like_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_NUMERIC_LABEL.match(host.rsplit(".", 1)[-1]))


def parse_url(raw: str) -> ParsedURL:
    """Validate and normalise `raw`, then split it into parts.

    Normalisation: trim spaces, assume https:// when no scheme is given
    (browsers try HTTPS first today), lower-case the host, punycode-encode it,
    and drop the #fragment (it never reaches the server and would split the
    cache for the same page).
    """
    raw = (raw or "").strip()
    if not raw:
        raise InvalidURL("URL is empty")
    if len(raw) > 4096:
        raise InvalidURL("URL is longer than 4096 characters")
    if not _HAS_SCHEME.match(raw):
        if _DANGEROUS_SCHEME.match(raw):
            raise InvalidURL("only http and https URLs can be scanned")
        raw = "https://" + raw

    try:
        parts = urlsplit(raw)
        port = parts.port  # raises ValueError for ports like :99999 or :abc
    except ValueError as exc:
        raise InvalidURL(f"malformed URL: {exc}") from exc

    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise InvalidURL("only http and https URLs can be scanned")

    hostname = (parts.hostname or "").rstrip(".")
    if not hostname:
        raise InvalidURL("URL has no host name")

    if hostname.isascii():
        host = hostname
        unicode_host = _to_unicode(hostname) if "xn--" in hostname else hostname
    else:
        host = _to_ascii(hostname)
        unicode_host = hostname

    is_ip = _looks_like_ip(host)
    if is_ip:
        subdomain, domain, suffix = "", host, ""
    else:
        ext = _EXTRACT(host)
        subdomain, domain, suffix = ext.subdomain, ext.domain, ext.suffix

    userinfo, _, _ = parts.netloc.rpartition("@")
    netloc = (userinfo + "@" if userinfo else "") + (f"[{host}]" if ":" in host else host)
    if port is not None:
        netloc += f":{port}"
    path = parts.path or "/"
    url = urlunsplit((scheme, netloc, path, parts.query, ""))

    return ParsedURL(
        url=url, scheme=scheme, host=host, unicode_host=unicode_host, port=port,
        path=path, query=parts.query, subdomain=subdomain, domain=domain,
        suffix=suffix, is_ip=is_ip, has_userinfo=bool(userinfo),
    )
