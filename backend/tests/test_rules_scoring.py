import pytest

from phishguard.features.lexical import extract_lexical
from phishguard.rules import Reason, host_rules, lexical_rules, page_rules
from phishguard.scoring import combine, is_known_good, verdict_for


def ids(reasons):
    return {r.id for r in reasons}


def test_noisy_or_combination():
    rules = [Reason("a", "rule", 0.5, "x"), Reason("b", "rule", 0.5, "y")]
    # 1 - (1 - 0.2) * 0.5 * 0.5 = 0.8
    assert combine(0.2, rules, known_good=False) == pytest.approx(0.8)


def test_model_and_info_reasons_do_not_add_risk():
    reasons = [Reason("model:x", "model", 0.0, "m"), Reason("info", "rule", 0.0, "i")]
    assert combine(0.3, reasons, known_good=False) == pytest.approx(0.3)


def test_known_good_cap():
    assert combine(0.99, [Reason("a", "rule", 0.9, "x")], known_good=True) == pytest.approx(0.10)


def test_known_good_excludes_user_content_platforms():
    assert is_known_good(extract_lexical("https://docs.python.org/3/"))
    assert is_known_good(extract_lexical("https://mail.google.com/mail/u/0/"))
    assert not is_known_good(extract_lexical("https://sites.google.com/view/anything"))
    assert not is_known_good(extract_lexical("https://someone.github.io/"))


@pytest.mark.parametrize("score,verdict", [(0, "safe"), (39, "safe"), (40, "suspicious"),
                                           (69, "suspicious"), (70, "phishing"), (100, "phishing")])
def test_verdict_bands(score, verdict):
    assert verdict_for(score) == verdict


def test_severity_from_weight():
    assert Reason("a", "rule", 0.6, "x").severity == "high"
    assert Reason("a", "rule", 0.3, "x").severity == "medium"
    assert Reason("a", "rule", 0.1, "x").severity == "low"
    assert Reason("a", "rule", 0.0, "x").severity == "info"


def test_lexical_rules_fire_on_their_tricks():
    assert "homoglyph" in ids(lexical_rules(extract_lexical("https://аpple.com/")))
    assert "typosquat" in ids(lexical_rules(extract_lexical("http://paypa1.com/")))
    assert "ip_host" in ids(lexical_rules(extract_lexical("http://45.33.12.9/login")))
    assert "at_symbol" in ids(lexical_rules(extract_lexical("http://bank.com@evil.example/")))
    assert "brand_in_host" in ids(lexical_rules(extract_lexical("http://paypal-secure.example/")))
    assert lexical_rules(extract_lexical("https://example.com/about")) == []


def test_brand_in_path_needs_a_suspicious_word():
    # A news article about Apple is fine; "apple" next to "verify" is not.
    assert "brand_in_path" not in ids(lexical_rules(extract_lexical("https://news.example/apple-iphone-review")))
    assert "brand_in_path" in ids(lexical_rules(extract_lexical("https://shop.example/apple/verify")))


def test_host_rules():
    young = {"blocked": None, "whois": {"age_days": 5}, "tls": {"https": True, "valid": False,
                                                                 "error": "certificate has expired"}, "dns": {}}
    assert {"new_domain", "tls_invalid"} <= ids(host_rules(young))
    old = {"blocked": None, "whois": {"age_days": 4000}, "tls": {"https": True, "valid": True, "age_days": 40,
                                                                  "issuer": "CA"}, "dns": {}}
    assert all(r.weight == 0 for r in host_rules(old))
    assert ids(host_rules({"blocked": "private"})) == {"network_skipped"}


def test_page_rules():
    lex = extract_lexical("http://paypal-help.example.org/login")
    page = {"final_url": lex.parsed.url, "final_is_https": False, "form_count": 1, "password_fields": 1,
            "brands_in_title": ["paypal"], "external_password_form": True, "external_form_count": 1,
            "mailto_form": False, "forms": [{"action": "https://c.example/x", "kind": "external",
                                             "has_password": True}]}
    assert {"brand_login_page", "password_form_external", "password_over_http"} <= ids(page_rules(page, lex))


def test_page_rules_cross_domain_redirect():
    lex = extract_lexical("https://bit.ly/abc")
    page = {"final_url": "https://landing.example.net/", "form_count": 0, "password_fields": 0,
            "final_is_https": True}
    assert "cross_domain_redirect" in ids(page_rules(page, lex))
