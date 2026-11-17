"""Send a mix of URLs through the running API so the dashboard has data.

Run from backend/ while the API is running:

    ..\\.venv\\Scripts\\python.exe scripts\\demo_scans.py

The phishing-style URLs are made up (they imitate common tricks) and are only
sent as QUICK scans, which never contact the host. Deep scans are used only
for well-known real sites.
"""
from __future__ import annotations

import sys
import time

import httpx

API = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"

QUICK = [
    "http://paypal.com.secure-login.verify-account.xyz/signin",
    "https://аpple.com/login",
    "http://paypa1-support.com/verify",
    "http://45.33.12.9/secure/login.php",
    "http://rnicrosoft-office365.com/owa/auth/logon.aspx",
    "https://secure-hdfcbank-kyc.top/login",
    "http://netfIix-billing-update.com/account",
    "https://docs-sign-in.netlify.app/?email=victim@example.com",
    "http://bank.com@login-check.example.net/session",
    "https://sbi-yono-rewards.click/claim-points",
    "http://update-your-account.weebly.com/",
    "https://amaz0n-orders.support/refund/verify",
    "http://hacked-bakery.example/wp-content/www.paypal.com/login.php",
    "https://irctc-refund-status.online/kyc/update",
    "https://github.com/vercel/next.js",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://www.amazon.in/gp/your-account/order-history",
    "https://stackoverflow.com/questions/tagged/python",
    "https://news.ycombinator.com/",
    "https://www.irctc.co.in/nget/train-search",
    "https://pypi.org/project/fastapi/",
    "https://myblog.dev/posts/how-i-built-a-phishing-detector",
    "https://bit.ly/3xYz",
    "https://shop.example-store.com/products/blue-mug",
]
DEEP = [
    "https://github.com/login",
    "https://www.python.org/downloads/",
    "https://en.wikipedia.org/wiki/Main_Page",
]


def scan(client: httpx.Client, url: str, mode: str, source: str) -> dict:
    """POST one scan; on HTTP 429 wait as long as Retry-After says, then retry."""
    while True:
        resp = client.post("/api/scan", json={"url": url, "mode": mode}, headers={"X-PhishGuard-Client": source})
        if resp.status_code != 429:
            resp.raise_for_status()
            return resp.json()
        wait = int(resp.headers.get("Retry-After", "2"))
        print(f"    rate limited, waiting {wait}s")
        time.sleep(wait)


def main() -> None:
    with httpx.Client(base_url=API, timeout=30) as client:
        for i, url in enumerate(QUICK):
            source = "extension" if i % 3 == 0 else "web"  # mimic both clients
            body = scan(client, url, "fast", source)
            print(f"{body['score']:3d} {body['verdict']:10s} quick {url}")
        for url in DEEP:
            body = scan(client, url, "full", "web")
            print(f"{body['score']:3d} {body['verdict']:10s} deep  {url}")
        # Repeat a few scans to show the cache at work.
        for url in QUICK[:6]:
            scan(client, url, "fast", "extension")


if __name__ == "__main__":
    main()
