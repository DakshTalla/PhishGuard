"""Turn model contributions into sentences a non-expert can read.

Two outputs, on purpose:
  * breakdown(): every feature with its value and raw contribution, for the
    "feature breakdown" panel (complete and honest, but technical);
  * model_reasons(): at most a few sentences, only for features that pushed
    towards phishing AND whose value is unusual in the risky direction.
    A tree model can give "34 characters long" a positive push because of an
    interaction with other features; telling a user "risky: the URL is short"
    would be confusing, so the plausibility check filters it out. The raw
    number is still visible in the breakdown.
"""
from __future__ import annotations

from typing import Callable

from ..features.brands import BRAND_DISPLAY
from ..features.lexical import FEATURE_NAMES, LexicalResult
from ..rules import Reason
from .predictor import Prediction

# Contributions are in log-odds; 0.4 is about a 1.5x change in the odds.
MIN_CONTRIBUTION = 0.4
MAX_MODEL_REASONS = 4

LABELS: dict[str, str] = {
    "url_length": "URL length", "host_length": "Host length", "path_length": "Path length",
    "query_length": "Query length", "num_dots_host": "Dots in host",
    "num_hyphens_host": "Hyphens in host", "num_digits_host": "Digits in host",
    "digit_ratio_url": "Digit ratio", "subdomain_depth": "Subdomain depth",
    "domain_entropy": "Domain randomness", "url_entropy": "URL randomness",
    "path_depth": "Path depth", "num_query_params": "Query parameters",
    "num_special_chars": "Special characters", "num_percent_encoded": "Percent-encoded chars",
    "longest_token_length": "Longest token", "suspicious_word_count": "Suspicious words",
    "is_https": "Uses HTTPS", "has_ip_host": "IP address host", "has_port": "Custom port",
    "has_at_symbol": "'@' before host", "has_double_slash_path": "'//' in path",
    "has_email_in_url": "Email in URL", "is_punycode": "Punycode domain",
    "has_non_ascii": "Non-ASCII domain", "suspicious_tld": "Abused TLD",
    "is_shortener": "URL shortener", "free_hosting": "Free hosting platform",
    "tld_in_subdomain": "TLD inside subdomain", "brand_in_host": "Brand in host",
    "brand_in_path": "Brand in path", "domain_in_path": "Domain name in path",
    "script_endpoint": "Script endpoint (.php)", "wordpress_path": "WordPress folder in path",
}
assert set(LABELS) == set(FEATURE_NAMES)

# feature -> function(value, lexical result) returning a sentence, or None when
# the value is not unusual in the risky direction.
Describer = Callable[[float, LexicalResult], "str | None"]


def _brands(names: list[str]) -> str:
    return ", ".join(BRAND_DISPLAY.get(b, b) for b in names) or "a brand"


DESCRIBE: dict[str, Describer] = {
    "url_length": lambda v, _: f"Very long URL ({v:.0f} characters) can push the real domain out of view" if v >= 75 else None,
    "host_length": lambda v, _: f"Long host name ({v:.0f} characters)" if v >= 30 else None,
    "path_length": lambda v, _: f"Long path ({v:.0f} characters)" if v >= 60 else None,
    "query_length": lambda v, _: f"Long query string ({v:.0f} characters)" if v >= 60 else None,
    "num_dots_host": lambda v, _: f"Host has {v:.0f} dots; extra labels can fake a familiar domain" if v >= 4 else None,
    "num_hyphens_host": lambda v, _: f"Host has {v:.0f} hyphens (pattern like secure-login-bank)" if v >= 2 else None,
    "num_digits_host": lambda v, _: f"Host contains {v:.0f} digits" if v >= 3 else None,
    "digit_ratio_url": lambda v, _: f"{v:.0%} of the URL is digits" if v >= 0.15 else None,
    "subdomain_depth": lambda v, _: f"{v:.0f} levels of subdomains" if v >= 2 else None,
    "domain_entropy": lambda v, lex: f"Domain name '{lex.parsed.domain}' looks randomly generated" if v >= 3.5 else None,
    "url_entropy": lambda v, _: "URL text looks randomly generated" if v >= 4.9 else None,
    "path_depth": lambda v, _: f"Deep path ({v:.0f} folders)" if v >= 5 else None,
    "num_query_params": lambda v, _: f"{v:.0f} query parameters" if v >= 4 else None,
    "num_special_chars": lambda v, _: f"{v:.0f} special characters (- _ = & % ...)" if v >= 10 else None,
    "num_percent_encoded": lambda v, _: f"{v:.0f} percent-encoded characters hide parts of the URL" if v >= 3 else None,
    "longest_token_length": lambda v, _: f"Contains a {v:.0f}-character random-looking string" if v >= 25 else None,
    "suspicious_word_count": lambda v, lex: f"Uses words common in phishing: {', '.join(lex.suspicious_words)}" if v >= 1 else None,
    "is_https": lambda v, _: "Does not use HTTPS" if v == 0 else None,
    "has_ip_host": lambda v, _: "Uses an IP address instead of a domain name" if v else None,
    "has_port": lambda v, lex: f"Uses unusual port {lex.parsed.port}" if v else None,
    "has_at_symbol": lambda v, _: "Has '@' before the host name" if v else None,
    "has_double_slash_path": lambda v, _: "Has '//' inside the path (redirect trick)" if v else None,
    "has_email_in_url": lambda v, _: "Contains an email address" if v else None,
    "is_punycode": lambda v, _: "Internationalised (punycode) domain" if v else None,
    "has_non_ascii": lambda v, _: "Domain contains non-ASCII characters" if v else None,
    "suspicious_tld": lambda v, lex: f"Uses .{lex.parsed.tld}, a frequently abused TLD" if v else None,
    "is_shortener": lambda v, _: "URL shortener hides the destination" if v else None,
    "free_hosting": lambda v, lex: f"Hosted on a free platform ({lex.platform})" if v else None,
    "tld_in_subdomain": lambda v, _: "A TLD such as '.com' appears inside the subdomain" if v else None,
    "brand_in_host": lambda v, lex: f"Brand name ({_brands(lex.brands_in_host)}) in a host that does not belong to it" if v else None,
    "brand_in_path": lambda v, lex: f"Brand name ({_brands(lex.brands_in_path)}) in the path of an unrelated site" if v else None,
    "domain_in_path": lambda v, _: "Another site's domain name appears inside the path" if v else None,
    "script_endpoint": lambda v, _: "Points straight at a server script (.php/.asp) that can collect form data" if v else None,
    "wordpress_path": lambda v, _: "Served from WordPress system folders, a common spot for kits on hacked sites" if v else None,
}
assert set(DESCRIBE) == set(FEATURE_NAMES)


def breakdown(lex: LexicalResult, pred: Prediction) -> list[dict]:
    """All features sorted by absolute contribution (largest effect first)."""
    rows = [
        {"feature": name, "label": LABELS[name], "value": round(lex.features[name], 4),
         "contribution": round(pred.contributions[name], 4)}
        for name in FEATURE_NAMES
    ]
    return sorted(rows, key=lambda r: abs(r["contribution"]), reverse=True)


def model_reasons(lex: LexicalResult, pred: Prediction) -> list[Reason]:
    """Plain-language reasons for the features that raised the risk most."""
    reasons = []
    for name, contrib in sorted(pred.contributions.items(), key=lambda kv: kv[1], reverse=True):
        if contrib < MIN_CONTRIBUTION or len(reasons) >= MAX_MODEL_REASONS:
            break
        sentence = DESCRIBE[name](lex.features[name], lex)
        if sentence:
            # weight 0: the model's effect is already inside its probability;
            # this Reason only explains it, it must not be counted twice.
            reasons.append(Reason(id=f"model:{name}", source="model", weight=0.0,
                                  message=sentence, feature=name,
                                  severity="high" if contrib >= 1.5 else "medium" if contrib >= 0.8 else "low"))
    return reasons
