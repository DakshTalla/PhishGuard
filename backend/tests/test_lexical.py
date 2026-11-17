import pytest

from phishguard.features.lexical import FEATURE_NAMES, brand_matches, extract_lexical, shannon_entropy


def test_vector_matches_feature_list():
    lex = extract_lexical("https://example.com/")
    assert len(lex.vector()) == len(FEATURE_NAMES)
    assert all(isinstance(v, float) for v in lex.vector())


def test_classic_phishing_url_lights_up_expected_features():
    lex = extract_lexical("http://paypal.com.secure-login.verify-account.xyz/signin?email=a@b.com")
    f = lex.features
    assert f["is_https"] == 0
    assert f["suspicious_tld"] == 1
    assert f["tld_in_subdomain"] == 1
    assert f["brand_in_host"] == 1 and lex.brands_in_host == ["paypal"]
    assert f["has_email_in_url"] == 1
    assert {"login", "verify", "account", "secure", "signin"} <= set(lex.suspicious_words)


def test_brand_on_its_own_domain_is_not_impersonation():
    lex = extract_lexical("https://www.paypal.com/signin")
    assert lex.features["brand_in_host"] == 0


def test_www_does_not_change_host_features():
    # Regression: "one dot in host" used to act as a proxy for "no www".
    a = extract_lexical("https://www.example.com/docs").features
    b = extract_lexical("https://example.com/docs").features
    for name in ("host_length", "num_dots_host", "url_length", "subdomain_depth", "url_entropy"):
        assert a[name] == b[name], name


@pytest.mark.parametrize("token,brand,expected", [
    ("mypaypal", "paypal", True),      # 6+ letters: anywhere
    ("appleid", "apple", True),        # 4-5 letters: prefix
    ("pineapple", "apple", False),
    ("purchase", "chase", False),
    ("sbi", "sbi", True),              # short: whole token only
    ("sbinet", "sbi", False),
])
def test_brand_matching_strictness(token, brand, expected):
    assert brand_matches(token, brand) is expected


def test_hyphenated_suspicious_words_count():
    assert "signin" in extract_lexical("https://x.example/sign-in").suspicious_words


def test_at_in_path_is_not_the_userinfo_trick():
    assert extract_lexical("https://medium.com/@someone/post").features["has_at_symbol"] == 0
    assert extract_lexical("http://bank.com@evil.example/").features["has_at_symbol"] == 1


def test_path_signals():
    f = extract_lexical("http://hacked.example/wp-content/www.paypal.com/login.php").features
    assert f["wordpress_path"] == 1 and f["domain_in_path"] == 1 and f["script_endpoint"] == 1


def test_platform_and_shortener_detection():
    assert extract_lexical("https://login-verify.netlify.app/").platform == "netlify.app"
    assert extract_lexical("https://bit.ly/abc").shortener == "bit.ly"


def test_entropy():
    assert shannon_entropy("") == 0
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("ab") == 1.0
    assert shannon_entropy("xk29qfz7") > shannon_entropy("google")
