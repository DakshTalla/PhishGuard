import pytest

from phishguard.features.parsing import InvalidURL, parse_url


def test_adds_https_and_drops_fragment():
    p = parse_url("  Example.COM/a?b=1#section ")
    assert p.url == "https://example.com/a?b=1"
    assert p.scheme == "https" and p.host == "example.com"


def test_splits_registrable_domain_with_public_suffix_list():
    p = parse_url("http://mail.login.example.co.uk/")
    assert (p.subdomain, p.domain, p.suffix) == ("mail.login", "example", "co.uk")
    assert p.registrable_domain == "example.co.uk"
    assert p.tld == "uk"


@pytest.mark.parametrize("raw", ["", "javascript:alert(1)", "data:text/html,hi", "file:///C:/x",
                                 "ftp://example.com/", "http://", "http://example.com:99999/"])
def test_rejects_unscannable_input(raw):
    with pytest.raises(InvalidURL):
        parse_url(raw)


def test_internationalised_host_is_punycoded_but_remembered():
    p = parse_url("https://аpple.com/")  # Cyrillic "а"
    assert p.host == "xn--pple-43d.com"
    assert p.unicode_host == "аpple.com"


def test_punycode_input_is_decoded_for_humans():
    assert parse_url("https://xn--pple-43d.com").unicode_host == "аpple.com"


@pytest.mark.parametrize("raw", ["http://192.168.0.1/", "http://3232235777/", "http://0xC0A80001/", "http://[::1]/"])
def test_ip_hosts_in_any_notation(raw):
    assert parse_url(raw).is_ip


def test_userinfo_trick_is_detected_and_real_host_kept():
    p = parse_url("http://paypal.com@evil.example/login")
    assert p.has_userinfo and p.host == "evil.example"
