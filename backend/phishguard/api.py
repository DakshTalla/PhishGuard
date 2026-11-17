"""FastAPI app: scan endpoint with caching and rate limiting, plus admin views.

Start it with:  ..\\.venv\\Scripts\\python.exe -m uvicorn phishguard.main:app --port 8000

    POST /api/scan                 {"url": "...", "mode": "fast" | "full"}
    GET  /api/health
    GET  /api/admin/stats          totals, verdict mix, latency, scans per day
    GET  /api/admin/history        recent scans (?limit=&verdict=&q=)
    GET  /api/admin/scans/{id}     one stored scan in full
    GET  /api/admin/top-domains    most-flagged registrable domains
    GET  /api/admin/metrics        model metrics written by training

Endpoints are plain `def` (not async) on purpose: DNS, WHOIS and TLS libraries
block, and FastAPI runs sync endpoints in a thread pool so they do not freeze
the event loop.
"""
from __future__ import annotations

import json
import logging
import math
import secrets
import time
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from . import __version__
from .cache import TTLCache
from .config import Settings
from .features.parsing import InvalidURL, parse_url
from .model.predictor import Predictor
from .ratelimit import TokenBucketLimiter
from .scanner import Scanner
from .store import ScanStore

log = logging.getLogger("phishguard")


class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096, examples=["http://paypal.com.secure-login.xyz/verify"])
    mode: Literal["fast", "full"] = "fast"


def create_app(settings: Settings | None = None, scanner: Scanner | None = None) -> FastAPI:
    """App factory: tests pass their own settings and a scanner with fake network."""
    settings = settings or Settings.from_env()
    model_file = settings.model_dir / "model.json"
    if scanner is None:
        if not model_file.exists():
            raise RuntimeError(f"{model_file} not found. Train first: python -m phishguard.model.train")
        scanner = Scanner(Predictor.load(settings.model_dir),
                          host_cache=TTLCache(max_items=2000, ttl_seconds=settings.host_cache_ttl))
    metrics = json.loads((settings.model_dir / "metrics.json").read_text(encoding="utf-8"))
    store = ScanStore(settings.db_path)
    cache = TTLCache(max_items=5000, ttl_seconds=settings.scan_cache_ttl)
    limiter = TokenBucketLimiter(settings.rate_capacity, settings.rate_refill_per_sec)
    if not settings.admin_token:
        log.warning("PHISHGUARD_ADMIN_TOKEN is not set: admin endpoints are open (local use only)")

    app = FastAPI(title="PhishGuard API", version=__version__,
                  description="Phishing and malicious URL detection with explainable scores.")
    app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins),
                       allow_methods=["GET", "POST"], allow_headers=["*"])
    # Exposed for tests and the benchmark script.
    app.state.cache, app.state.limiter, app.state.store = cache, limiter, store

    def require_admin(x_admin_token: str | None = Header(default=None)) -> None:
        # compare_digest takes the same time whether the first or last
        # character differs, so the token cannot be guessed by timing.
        if settings.admin_token and not secrets.compare_digest(x_admin_token or "", settings.admin_token):
            raise HTTPException(status_code=401, detail="admin token required (X-Admin-Token header)")

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__, "model_trained_at": metrics.get("trained_at")}

    @app.post("/api/scan")
    def scan(body: ScanRequest, request: Request,
             x_phishguard_client: str | None = Header(default=None)) -> dict:
        client_ip = request.client.host if request.client else "unknown"
        cost = settings.full_scan_cost if body.mode == "full" else 1
        allowed, wait = limiter.take(client_ip, cost)
        if not allowed:
            raise HTTPException(status_code=429, detail="rate limit exceeded",
                                headers={"Retry-After": str(math.ceil(wait))})
        try:
            key = f"{body.mode}:{parse_url(body.url).url}"
        except InvalidURL as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        started = time.perf_counter()
        cached = cache.get(key)
        if cached is not None:
            result = dict(cached, url=body.url, cached=True,
                          latency_ms=round((time.perf_counter() - started) * 1000, 3))
        else:
            result = scanner.scan(body.url, body.mode)
            cache.set(key, result)
            result = dict(result)  # copy, so scan_id below never leaks into the cache
        client = x_phishguard_client if x_phishguard_client in ("web", "extension") else "api"
        result["scan_id"] = store.record(result, client)
        return result

    @app.get("/api/admin/stats", dependencies=[Depends(require_admin)])
    def stats() -> dict:
        return {**store.stats(), "cache": cache.stats()}

    @app.get("/api/admin/history", dependencies=[Depends(require_admin)])
    def history(limit: int = Query(50, ge=1, le=500),
                verdict: Literal["safe", "suspicious", "phishing"] | None = None,
                q: str | None = Query(None, max_length=200)) -> list[dict]:
        return store.history(limit=limit, verdict=verdict, query=q)

    @app.get("/api/admin/scans/{scan_id}", dependencies=[Depends(require_admin)])
    def scan_detail(scan_id: int) -> dict:
        result = store.get(scan_id)
        if result is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return result

    @app.get("/api/admin/top-domains", dependencies=[Depends(require_admin)])
    def top_domains(limit: int = Query(10, ge=1, le=100)) -> list[dict]:
        return store.top_flagged_domains(limit)

    @app.get("/api/admin/metrics", dependencies=[Depends(require_admin)])
    def model_metrics() -> dict:
        return metrics

    return app

