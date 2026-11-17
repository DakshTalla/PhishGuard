"""Lexical features: everything we can learn from the URL string alone.

WHY the model uses only these: they cost microseconds and need no network, so
the browser extension can ask for a verdict before a page loads. They are also
the only features we can compute *identically* for years-old training URLs
(whose sites are long dead) and for live traffic. Host and page signals exist
too, but they feed the rules layer instead (see rules.py).

Every feature below is tied to a phishing technique in docs/STUDY_GUIDE.md.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import unquote

from .brands import (BRANDS, SHORTENERS, SUSPICIOUS_TLDS, SUSPICIOUS_WORDS,
                     USER_CONTENT_HOSTS, host_in, matching_suffix)
from .lookalike import LookalikeMatch, find_lookalike, is_mixed_script
from .parsing import ParsedURL, parse_url

# The model's inputs, in a fixed order. Changing this list means retraining.
FEATURE_NAMES: list[str] = [
    "url_length",             # long URLs bury the real domain
    "host_length",
    "path_length",
    "query_length",
    "num_dots_host",          # paypal.com.secure.example.xyz
    "num_hyphens_host",       # secure-login-paypal.com
    "num_digits_host",
    "digit_ratio_url",
    "subdomain_depth",        # labels left of the registrable domain (www ignored)
    "domain_entropy",         # randomness of the bought name: xk29qf.top
    "url_entropy",
    "path_depth",
    "num_query_params",
    "num_special_chars",
    "num_percent_encoded",    # %xx escapes hide words from filters
    "longest_token_length",
    "suspicious_word_count",  # login, verify, account, ...
    "is_https",
    "has_ip_host",
    "has_port",
    "has_at_symbol",          # http://paypal.com@evil.com goes to evil.com
    "has_double_slash_path",  # //redirect tricks
    "has_email_in_url",       # kits pre-fill the victim's address
    "is_punycode",
    "has_non_ascii",
    "suspicious_tld",
    "is_shortener",
    "free_hosting",           # netlify.app, weebly.com, ...
    "tld_in_subdomain",       # paypal.com.evil.xyz
    "brand_in_host",          # brand keyword in a host that is not the brand
    "brand_in_path",          # brand keyword in the path of a non-brand host
    "domain_in_path",         # evil.com/www.paypal.com/login: a fake "real" domain
    "script_endpoint",        # path ends in .php/.asp/...: a kit collecting form posts
    "wordpress_path",         # wp-content/wp-admin: kit uploaded to a hacked WordPress site
]

_TOKEN = re.compile(r"[a-z0-9]+")
_WORDISH = re.compile(r"[a-z0-9_-]+")
_EMAIL = re.compile(r"[a-z0-9._%+-]+@[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}", re.I)
_PERCENT = re.compile(r"%[0-9a-f]{2}", re.I)
_SPECIAL = set("-_~%=&@!*,;$+")
# Something that looks like a host name inside the path, e.g. "/www.spk.de/".
_DOMAIN_IN_PATH = re.compile(
    r"(?:[a-z0-9-]+\.)+(?:com|net|org|de|ru|br|in|uk|info|biz|co|io|gov|edu|fr|it|es|pl)(?:[/:?]|$)")
_SCRIPT_EXT = (".php", ".asp", ".aspx", ".jsp", ".cgi")
_WP_DIRS = ("wp-content", "wp-admin", "wp-includes")
# A whole subdomain label that is a generic TLD (paypal.com.evil.xyz), or a
# bought name starting "com-" (runescape.com-en.ru), means the attacker wants
# the start of the host to look like a real domain.
_TLD_WORDS = {"com", "net", "org", "gov", "edu"}


@dataclass
class LexicalResult:
    parsed: ParsedURL
    features: dict[str, float]                 # model inputs, keyed by FEATURE_NAMES
    suspicious_words: list[str] = field(default_factory=list)
    brands_in_host: list[str] = field(default_factory=list)
    brands_in_path: list[str] = field(default_factory=list)
    lookalike: LookalikeMatch | None = None
    mixed_script: bool = False
    platform: str | None = None                # matched free-hosting suffix
    shortener: str | None = None

    def vector(self) -> list[float]:
        return [self.features[name] for name in FEATURE_NAMES]

    def to_dict(self) -> dict:
        """JSON-friendly view for the API and the frontend feature breakdown."""
        p = self.parsed
        return {
            "features": self.features,
            "host": p.host,
            "unicode_host": p.unicode_host,
            "registrable_domain": p.registrable_domain,
            "subdomain": p.subdomain,
            "suffix": p.suffix,
            "suspicious_words": self.suspicious_words,
            "brands_in_host": self.brands_in_host,
            "brands_in_path": self.brands_in_path,
            "lookalike": self.lookalike.__dict__ if self.lookalike else None,
            "mixed_script": self.mixed_script,
            "platform": self.platform,
            "shortener": self.shortener,
        }


def shannon_entropy(text: str) -> float:
    """Bits per character. 'google' ~1.9, 'xk29qfz7' ~3.0 (random-looking)."""
    if not text:
        return 0.0
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in Counter(text).values())


def brand_matches(token: str, brand: str) -> bool:
    """Does a URL token contain `brand`? Strictness depends on brand length.

    6+ letters: anywhere ("mypaypal").  4-5 letters: at the start ("appleid",
    "hdfcbank").  Shorter: whole token only ("sbi", "dhl"). This keeps
    "pineapple" from counting as Apple and "purchase" as Chase.
    """
    if len(brand) >= 6:
        return brand in token
    if len(brand) >= 4:
        return token.startswith(brand)
    return token == brand


def _brands_in(tokens: list[str], host: str) -> list[str]:
    found = []
    for brand, domains in BRANDS.items():
        if host_in(host, domains):
            continue  # paypal.com talking about PayPal is fine
        if any(brand_matches(t, brand) for t in tokens):
            found.append(brand)
    return found


def extract_lexical(url: str | ParsedURL) -> LexicalResult:
    """Compute all lexical features for one URL."""
    p = url if isinstance(url, ParsedURL) else parse_url(url)
    # WHY drop a leading "www." before measuring: www.example.com and
    # example.com are the same site. In the training data 67% of legitimate
    # URLs but only 21% of phishing URLs carry "www.", because of how the
    # legitimate ones were crawled. Left in, "host has one dot" became a proxy
    # for "no www" and the model flagged github.com/... as phishing.
    host = p.host[4:] if p.host.startswith("www.") else p.host
    full = p.url.lower().replace("://www.", "://", 1)
    after_scheme = full.split("://", 1)[1]
    host_tokens = _TOKEN.findall(".".join(x for x in (p.subdomain, p.domain) if x))
    path_tokens = _TOKEN.findall(unquote(p.path.lower()))
    all_tokens = _TOKEN.findall(unquote(after_scheme))

    sub_labels = [s for s in p.subdomain.split(".") if s]
    if sub_labels and sub_labels[0] == "www":
        sub_labels = sub_labels[1:]  # "www" is convention, not depth

    # Hyphens and underscores are dropped first so "sign-in" and "log_in" count.
    word_tokens = [t.replace("-", "").replace("_", "") for t in _WORDISH.findall(unquote(after_scheme))]
    words = sorted({w for w in SUSPICIOUS_WORDS if any(w in t for t in word_tokens)})
    brands_host = _brands_in(host_tokens, p.host)
    brands_path = [b for b in _brands_in(path_tokens, p.host) if b not in brands_host]
    platform = matching_suffix(p.host, USER_CONTENT_HOSTS)
    shortener = p.host if p.host in SHORTENERS else None
    query_text = unquote(p.query)
    path_lower = unquote(p.path).lower()

    features: dict[str, float] = {
        "url_length": len(full),
        "host_length": len(host),
        "path_length": len(p.path),
        "query_length": len(p.query),
        "num_dots_host": host.count("."),
        "num_hyphens_host": host.count("-"),
        "num_digits_host": sum(c.isdigit() for c in host),
        "digit_ratio_url": sum(c.isdigit() for c in full) / len(full),
        "subdomain_depth": len(sub_labels),
        "domain_entropy": shannon_entropy(p.domain),
        "url_entropy": shannon_entropy(after_scheme),
        "path_depth": len([s for s in p.path.split("/") if s]),
        "num_query_params": len([q for q in p.query.split("&") if q]),
        "num_special_chars": sum(c in _SPECIAL for c in after_scheme),
        "num_percent_encoded": len(_PERCENT.findall(full)),
        "longest_token_length": max((len(t) for t in all_tokens), default=0),
        "suspicious_word_count": len(words),
        "is_https": int(p.scheme == "https"),
        "has_ip_host": int(p.is_ip),
        "has_port": int(p.port is not None and p.port not in (80, 443)),
        # Only "@" before the host is the browser trick; "@" in a path is
        # normal (medium.com/@user) and emails are counted separately.
        "has_at_symbol": int(p.has_userinfo),
        "has_double_slash_path": int("//" in p.path),
        "has_email_in_url": int(bool(_EMAIL.search(unquote(p.path)) or _EMAIL.search(query_text))),
        "is_punycode": int("xn--" in p.host),
        "has_non_ascii": int(not p.unicode_host.isascii()),
        "suspicious_tld": int(p.tld in SUSPICIOUS_TLDS),
        "is_shortener": int(shortener is not None),
        "free_hosting": int(platform is not None),
        "tld_in_subdomain": int(any(lbl in _TLD_WORDS for lbl in p.subdomain.split("."))
                                or p.domain.startswith(("com-", "net-", "org-"))),
        "brand_in_host": int(bool(brands_host)),
        "brand_in_path": int(bool(brands_path)),
        "domain_in_path": int(bool(_DOMAIN_IN_PATH.search(path_lower))),
        "script_endpoint": int(path_lower.endswith(_SCRIPT_EXT)),
        "wordpress_path": int(any(d in path_lower for d in _WP_DIRS)),
    }
    features = {k: float(v) for k, v in features.items()}

    return LexicalResult(
        parsed=p,
        features=features,
        suspicious_words=words,
        brands_in_host=brands_host,
        brands_in_path=brands_path,
        lookalike=find_lookalike(p),
        mixed_script=is_mixed_script(p.unicode_host),
        platform=platform,
        shortener=shortener,
    )
