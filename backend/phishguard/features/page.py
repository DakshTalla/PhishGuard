"""Page features: fetch the HTML (safely) and look for credential theft.

What a phishing page has to do is collect secrets, so we look for exactly
that: password fields, forms that post somewhere else, and a page title
claiming to be a brand the domain does not belong to.

Limits, on purpose:
  * static HTML only: we never run JavaScript (kits that build the form in JS
    are missed; running untrusted JS on the server is a far bigger risk);
  * at most 1 MB, 5 redirects and ~6 seconds in total;
  * every redirect hop goes through the SSRF guard again.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx
from bs4 import BeautifulSoup

from .brands import BRANDS, host_in
from .lexical import brand_matches
from .netguard import BlockedAddress, resolve_public
from .parsing import InvalidURL, parse_url

MAX_BYTES = 1_000_000
MAX_REDIRECTS = 5
USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/131.0 Safari/537.36 PhishGuard/1.0")
_TOKEN = re.compile(r"[a-z0-9]+")


@dataclass
class FetchResult:
    final_url: str
    status: int | None = None
    html: str = ""
    redirects: list[str] = field(default_factory=list)
    error: str | None = None


def fetch_page(url: str, total_timeout: float = 6.0) -> FetchResult:
    """GET a page, following redirects by hand so each hop is re-checked.

    TLS verification is off for this fetch only: an invalid certificate is
    reported separately by host.py, and we still want to see what the page
    asks for. We only read the HTML; nothing is ever submitted.
    """
    deadline = time.monotonic() + total_timeout
    result = FetchResult(final_url=url)
    current = url
    with httpx.Client(follow_redirects=False, verify=False,
                      headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.5"}) as client:
        for _ in range(MAX_REDIRECTS + 1):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                result.error = "timeout"
                return result
            try:
                parsed = parse_url(current)
                resolve_public(parsed.host, parsed.port or (443 if parsed.scheme == "https" else 80))
                with client.stream("GET", parsed.url, timeout=remaining) as resp:
                    result.status = resp.status_code
                    result.final_url = parsed.url
                    if resp.is_redirect and "location" in resp.headers:
                        current = urljoin(parsed.url, resp.headers["location"])
                        result.redirects.append(current)
                        continue
                    if "html" not in resp.headers.get("content-type", "text/html"):
                        result.error = f"not HTML ({resp.headers.get('content-type')})"
                        return result
                    body = bytearray()
                    for chunk in resp.iter_bytes():
                        body.extend(chunk)
                        if len(body) >= MAX_BYTES:
                            break  # stop reading: a huge page is not worth the memory
                    result.html = bytes(body[:MAX_BYTES]).decode(resp.encoding or "utf-8", errors="replace")
                    return result
            except BlockedAddress as exc:
                result.error = f"blocked: {exc}"
                return result
            except InvalidURL as exc:
                result.error = f"bad redirect target: {exc}"
                return result
            except httpx.HTTPError as exc:
                result.error = f"fetch failed: {exc.__class__.__name__}"
                return result
    result.error = "too many redirects"
    return result


def _registrable(url: str) -> str | None:
    try:
        return parse_url(url).registrable_domain
    except InvalidURL:
        return None


def analyze_html(html: str, page_url: str) -> dict:
    """Extract credential-theft signals from static HTML."""
    soup = BeautifulSoup(html, "html.parser")
    page = parse_url(page_url)
    page_domain = page.registrable_domain

    title = soup.title.get_text(" ", strip=True)[:200] if soup.title else ""
    site_name_tag = soup.find("meta", attrs={"property": "og:site_name"})
    site_name = (site_name_tag.get("content") or "")[:100] if site_name_tag else ""

    forms = []
    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip()
        target = urljoin(page_url, action) if action else page_url
        scheme = urlsplit(target).scheme.lower()
        has_password = form.find("input", attrs={"type": re.compile(r"^password$", re.I)}) is not None
        if scheme == "mailto":
            kind = "mailto"
        elif scheme in ("http", "https"):
            kind = "external" if _registrable(target) not in (page_domain, None) else "same-site"
        else:
            kind = "script"  # javascript: or data: action, handled in JS
        forms.append({"action": target[:200], "kind": kind, "has_password": has_password,
                      "method": (form.get("method") or "get").lower()})

    password_fields = len(soup.find_all("input", attrs={"type": re.compile(r"^password$", re.I)}))
    refresh = soup.find("meta", attrs={"http-equiv": re.compile(r"^refresh$", re.I)})
    refresh_target = None
    if refresh and "url=" in (refresh.get("content") or "").lower():
        refresh_target = urljoin(page_url, refresh["content"].split("=", 1)[1].strip(" '\""))

    title_tokens = _TOKEN.findall(f"{title} {site_name}".lower())
    text_tokens = set(_TOKEN.findall(soup.get_text(" ", strip=True)[:20000].lower()))
    brands_in_title = [b for b, doms in BRANDS.items()
                       if not host_in(page.host, doms) and any(brand_matches(t, b) for t in title_tokens)]
    brands_in_text = [b for b, doms in BRANDS.items()
                      if not host_in(page.host, doms) and any(brand_matches(t, b) for t in text_tokens)]

    return {
        "title": title,
        "forms": forms[:10],
        "form_count": len(forms),
        "password_fields": password_fields,
        "external_form_count": sum(f["kind"] == "external" for f in forms),
        "external_password_form": any(f["kind"] == "external" and f["has_password"] for f in forms),
        "mailto_form": any(f["kind"] == "mailto" for f in forms),
        "iframe_count": len(soup.find_all("iframe")),
        "meta_refresh_to": refresh_target,
        "brands_in_title": brands_in_title,
        "brands_in_text": brands_in_text[:10],
    }


def analyze_page(url: str) -> dict:
    """Fetch + analyse; always returns a dict, with `error` set on failure."""
    fetched = fetch_page(url)
    out: dict = {"final_url": fetched.final_url, "status": fetched.status,
                 "redirects": fetched.redirects, "error": fetched.error,
                 "final_is_https": fetched.final_url.startswith("https://")}
    if fetched.html:
        out.update(analyze_html(fetched.html, fetched.final_url))
    return out
