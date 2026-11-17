"""The rules layer: explicit checks that turn facts into scored reasons.

WHY rules next to a model:
  * some attacks are too rare in public data for a model to learn
    (homoglyphs, typosquats of a specific brand) but obvious once named;
  * host and page facts (domain age, password forms) cannot be computed for
    years-old training URLs, so no model can be trained on them here;
  * every rule is one readable sentence, which is what users act on.

Each rule has a `weight` between 0 and 1: "on its own, how sure would this
make me that the URL is phishing?" scoring.py combines the weights with the
model's probability (noisy-OR). The weights are expert judgement, written
down where they can be reviewed, and their effect is measured on the test
set by train.py ("model + rules" metrics).
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

from .features.brands import BRAND_DISPLAY, BRANDS
from .features.lexical import LexicalResult
from .features.parsing import InvalidURL, parse_url


@dataclass(frozen=True)
class Reason:
    id: str
    source: str                # "rule", "model" or "allowlist"
    weight: float              # 0 = informational only
    message: str
    severity: str = ""         # high / medium / low / info; derived from weight if empty
    feature: str | None = None # lexical feature this explains (avoids duplicate sentences)

    def __post_init__(self):
        if not self.severity:
            sev = ("high" if self.weight >= 0.5 else "medium" if self.weight >= 0.25
                   else "low" if self.weight > 0 else "info")
            object.__setattr__(self, "severity", sev)

    def to_dict(self) -> dict:
        return asdict(self)


def _rule(rule_id: str, weight: float, message: str, feature: str | None = None) -> Reason:
    return Reason(id=rule_id, source="rule", weight=weight, message=message, feature=feature)


def _brand(name: str) -> str:
    return BRAND_DISPLAY.get(name, name)


def lexical_rules(lex: LexicalResult) -> list[Reason]:
    """Checks on the URL string. Cheap, so they run in every scan."""
    p, f, out = lex.parsed, lex.features, []

    if lex.lookalike and lex.lookalike.kind == "homoglyph":
        out.append(_rule("homoglyph", 0.85,
                         f"Look-alike letters: '{p.unicode_host}' imitates {lex.lookalike.legit_domain} "
                         "using characters from another alphabet", "is_punycode"))
    elif lex.lookalike:
        out.append(_rule("typosquat", 0.6,
                         f"'{lex.lookalike.evidence}' imitates {_brand(lex.lookalike.brand)} "
                         f"({lex.lookalike.legit_domain}) with a one-character change"))
    elif lex.mixed_script:
        out.append(_rule("mixed_script", 0.5, "Domain mixes letters from different alphabets", "has_non_ascii"))
    elif f["is_punycode"]:
        out.append(_rule("punycode", 0.15, f"Internationalised domain shown as '{p.unicode_host}'", "is_punycode"))

    if lex.brands_in_host:
        b = lex.brands_in_host[0]
        out.append(_rule("brand_in_host", 0.5,
                         f"Mentions {_brand(b)} in the address, but the site is {p.registrable_domain}, "
                         f"not {BRANDS[b][0]}", "brand_in_host"))
    elif lex.brands_in_path and lex.suspicious_words:
        b = lex.brands_in_path[0]
        out.append(_rule("brand_in_path", 0.3,
                         f"Path mentions {_brand(b)} next to words like '{lex.suspicious_words[0]}' "
                         f"on an unrelated site ({p.registrable_domain})", "brand_in_path"))

    if p.is_ip:
        out.append(_rule("ip_host", 0.45, "Uses a raw IP address instead of a domain name", "has_ip_host"))
    if p.has_userinfo:
        out.append(_rule("at_symbol", 0.45,
                         f"Contains '@' before the host: the browser ignores the text before it "
                         f"and really opens {p.host}", "has_at_symbol"))
    if f["has_email_in_url"]:
        out.append(_rule("email_in_url", 0.2,
                         "Contains an email address; phishing kits pre-fill the victim's address",
                         "has_email_in_url"))
    if f["tld_in_subdomain"] and not lex.brands_in_host:
        out.append(_rule("tld_in_subdomain", 0.25,
                         f"Starts like a familiar domain but really belongs to {p.registrable_domain}",
                         "tld_in_subdomain"))
    if f["domain_in_path"]:
        out.append(_rule("domain_in_path", 0.3,
                         "Another site's domain name appears in the path to make the link look legitimate",
                         "domain_in_path"))
    if f["subdomain_depth"] >= 4:
        out.append(_rule("deep_subdomains", 0.25,
                         f"{f['subdomain_depth']:.0f} levels of subdomains hide the real domain", "subdomain_depth"))
    if lex.shortener:
        out.append(_rule("shortener", 0.15, f"Link shortener ({lex.shortener}) hides the real destination", "is_shortener"))
    if lex.platform:
        out.append(_rule("free_hosting", 0.15,
                         f"Hosted on {lex.platform}, where anyone can publish a page for free", "free_hosting"))
    if f["suspicious_tld"]:
        out.append(_rule("suspicious_tld", 0.15, f".{p.tld} is among the TLDs most abused for phishing", "suspicious_tld"))
    if f["has_port"]:
        out.append(_rule("odd_port", 0.2, f"Uses unusual port {p.port}", "has_port"))
    return out


def host_rules(host: dict | None) -> list[Reason]:
    """Checks on DNS, TLS and registration data (full scans only)."""
    if not host:
        return []
    if host.get("blocked"):
        return [_rule("network_skipped", 0.0, f"Network checks skipped: {host['blocked']}")]
    out = []
    whois = host.get("whois") or {}
    age = whois.get("age_days")
    if age is not None:
        if age < 30:
            out.append(_rule("new_domain", 0.6, f"Domain was registered only {age} days ago"))
        elif age < 180:
            out.append(_rule("young_domain", 0.25, f"Domain is young ({age} days old)"))
        elif age >= 730:
            out.append(_rule("old_domain", 0.0, f"Domain has existed for {age // 365} years"))

    tls = host.get("tls") or {}
    if tls.get("https") and not tls.get("valid"):
        out.append(_rule("tls_invalid", 0.35, f"TLS certificate failed verification ({tls.get('error')})"))
    elif tls.get("valid"):
        if tls.get("age_days") is not None and tls["age_days"] < 3:
            out.append(_rule("fresh_cert", 0.1, f"TLS certificate was issued {tls['age_days']} day(s) ago"))
        out.append(_rule("valid_cert", 0.0, f"Valid TLS certificate issued by {tls.get('issuer') or 'a trusted CA'}"))

    dns = host.get("dns") or {}
    if dns.get("error") == "NXDOMAIN":
        out.append(_rule("nxdomain", 0.1, "Domain does not exist in DNS (it may have been taken down)"))
    return out


def page_rules(page: dict | None, lex: LexicalResult) -> list[Reason]:
    """Checks on the fetched HTML (full scans only)."""
    if not page:
        return []
    if page.get("error") and "form_count" not in page:
        return [_rule("page_unavailable", 0.0, f"Page content not analysed: {page['error']}")]
    out = []
    domain = lex.parsed.registrable_domain
    has_password = page.get("password_fields", 0) > 0

    if page.get("brands_in_title") and has_password:
        b = page["brands_in_title"][0]
        out.append(_rule("brand_login_page", 0.7,
                         f"Page calls itself {_brand(b)} and asks for a password, but the site is "
                         f"{domain}, not {BRANDS[b][0]}"))
    if page.get("external_password_form"):
        target = next((f["action"] for f in page.get("forms", [])
                       if f["kind"] == "external" and f["has_password"]), "another site")
        out.append(_rule("password_form_external", 0.6, f"Login form sends your password to another site ({target})"))
    elif page.get("external_form_count"):
        out.append(_rule("form_external", 0.2, "A form on the page submits to a different site"))
    if page.get("mailto_form"):
        out.append(_rule("mailto_form", 0.4, "A form emails what you type to someone (mailto: action)"))
    if has_password and not page.get("final_is_https"):
        out.append(_rule("password_over_http", 0.6, "Page asks for a password over unencrypted HTTP"))

    final_url = page.get("meta_refresh_to") or page.get("final_url")
    try:
        final_domain = parse_url(final_url).registrable_domain if final_url else domain
    except InvalidURL:
        final_domain = domain
    if final_domain != domain:
        out.append(_rule("cross_domain_redirect", 0.15, f"Redirects to a different site: {final_domain}"))
    if not out and page.get("form_count") is not None and not has_password:
        out.append(_rule("no_credential_form", 0.0, "Page does not ask for a password"))
    return out
