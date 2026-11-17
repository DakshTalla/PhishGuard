"""End-to-end API tests with a scanner whose network lookups are fakes."""
import pytest
from fastapi.testclient import TestClient

from phishguard.api import create_app
from phishguard.config import Settings
from phishguard.scanner import Scanner


def fake_host(parsed):
    return {"blocked": None, "dns": {"resolves": True, "a": ["93.184.216.34"], "error": None},
            "tls": {"https": True, "valid": True, "issuer": "Test CA", "age_days": 1},
            "whois": {"age_days": 3, "created": "2026-11-14T00:00:00+00:00", "source": "rdap"}}


def fake_page(url):
    return {"final_url": url, "status": 200, "error": None, "final_is_https": url.startswith("https"),
            "title": "PayPal - Log In", "forms": [], "form_count": 1, "password_fields": 1,
            "external_form_count": 0, "external_password_form": False, "mailto_form": False,
            "iframe_count": 0, "meta_refresh_to": None, "brands_in_title": ["paypal"], "brands_in_text": []}


@pytest.fixture
def make_client(tmp_path, predictor):
    def factory(**overrides):
        settings = Settings(db_path=tmp_path / "scans.db", **overrides)
        scanner = Scanner(predictor, host_lookup=fake_host, page_lookup=fake_page)
        return TestClient(create_app(settings, scanner=scanner))
    return factory


def scan(client, url, mode="fast", **headers):
    return client.post("/api/scan", json={"url": url, "mode": mode}, headers=headers)


def test_fast_scan_shape(make_client):
    body = scan(make_client(), "http://paypal.com.secure-login.verify-account.xyz/signin").json()
    assert body["verdict"] == "phishing" and body["score"] >= 70
    assert body["domain"] == "verify-account.xyz"
    assert body["reasons"][0]["severity"] == "high"
    assert body["features"]["host"] is None  # fast mode makes no network calls
    assert len(body["contributions"]) > 20


def test_known_good_site_is_safe(make_client):
    body = scan(make_client(), "https://github.com/vercel/next.js").json()
    assert body["verdict"] == "safe" and body["known_good"]


def test_full_scan_adds_host_and_page_reasons(make_client):
    body = scan(make_client(), "http://paypal-help.example.org/login", mode="full").json()
    rule_ids = {r["id"] for r in body["reasons"]}
    assert {"new_domain", "brand_login_page", "password_over_http"} <= rule_ids
    assert body["score"] >= 90


def test_invalid_url_is_400(make_client):
    assert scan(make_client(), "javascript:alert(1)").status_code == 400
    assert make_client().post("/api/scan", json={"url": ""}).status_code == 422


def test_second_scan_is_served_from_cache(make_client):
    client = make_client()
    first = scan(client, "http://example.org/a#frag").json()
    second = scan(client, "http://EXAMPLE.org/a").json()  # same page after normalisation
    assert not first["cached"] and second["cached"]
    assert second["score"] == first["score"] and second["scan_id"] != first["scan_id"]


def test_rate_limit_returns_429_with_retry_after(make_client):
    client = make_client(rate_capacity=2, rate_refill_per_sec=0.5)
    assert scan(client, "https://a.example/").status_code == 200
    assert scan(client, "https://b.example/").status_code == 200
    blocked = scan(client, "https://c.example/")
    assert blocked.status_code == 429 and blocked.headers["Retry-After"] == "2"


def test_full_scans_cost_more(make_client):
    client = make_client(rate_capacity=5, full_scan_cost=5)
    assert scan(client, "https://a.example/", mode="full").status_code == 200
    assert scan(client, "https://b.example/").status_code == 429


def test_admin_endpoints_report_history(make_client):
    client = make_client()
    scan(client, "http://paypal.com.secure-login.verify-account.xyz/signin", **{"X-PhishGuard-Client": "extension"})
    scan(client, "https://github.com/")
    stats = client.get("/api/admin/stats").json()
    assert stats["total_scans"] == 2 and stats["by_client"] == {"extension": 1, "api": 1}
    assert stats["by_verdict"]["phishing"] == 1
    history = client.get("/api/admin/history?verdict=phishing").json()
    assert len(history) == 1 and history[0]["domain"] == "verify-account.xyz"
    top = client.get("/api/admin/top-domains").json()
    assert top[0]["domain"] == "verify-account.xyz"
    detail = client.get(f"/api/admin/scans/{history[0]['id']}").json()
    assert detail["verdict"] == "phishing"
    assert client.get("/api/admin/scans/9999").status_code == 404
    assert "test" in client.get("/api/admin/metrics").json()


def test_admin_token_is_enforced_when_set(make_client):
    client = make_client(admin_token="s3cret")
    assert client.get("/api/admin/stats").status_code == 401
    assert client.get("/api/admin/stats", headers={"X-Admin-Token": "wrong"}).status_code == 401
    assert client.get("/api/admin/stats", headers={"X-Admin-Token": "s3cret"}).status_code == 200
    assert scan(client, "https://example.com/").status_code == 200  # scanning stays public


def test_shortener_hint_in_fast_mode(make_client):
    body = scan(make_client(), "https://bit.ly/abc").json()
    assert any(r["id"] == "shortener_hint" for r in body["reasons"])
