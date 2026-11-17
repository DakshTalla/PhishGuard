"""The scan pipeline: URL -> features -> model -> rules -> one score + reasons.

    fast mode  lexical features, model, lexical rules           (~1-3 ms)
    full mode  + DNS/TLS/domain age and the fetched page, run
               in parallel with hard timeouts                    (~1-6 s)

The browser extension uses fast mode before a page loads; the web app and the
extension popup can ask for a full scan on demand.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Callable

from .cache import TTLCache
from .features.host import gather_host_intel
from .features.lexical import LexicalResult, extract_lexical
from .features.page import analyze_page
from .features.parsing import InvalidURL
from .model.explain import breakdown, model_reasons
from .model.predictor import Predictor
from .rules import Reason, host_rules, lexical_rules, page_rules
from .scoring import combine, is_known_good, score_of, verdict_for

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


class Scanner:
    def __init__(self, predictor: Predictor, *,
                 host_lookup: Callable[..., dict] = gather_host_intel,
                 page_lookup: Callable[[str], dict] = analyze_page,
                 host_cache: TTLCache | None = None):
        # Network lookups are injected so tests can replace them with fakes.
        self.predictor = predictor
        self.host_lookup = host_lookup
        self.page_lookup = page_lookup
        self.host_cache = host_cache or TTLCache(max_items=2000, ttl_seconds=6 * 3600)

    def _host_intel(self, lex: LexicalResult) -> dict:
        key = lex.parsed.host
        intel = self.host_cache.get(key)
        if intel is None:
            intel = self.host_lookup(lex.parsed)
            self.host_cache.set(key, intel)
        return intel

    def _network_checks(self, lex: LexicalResult) -> tuple[dict, dict]:
        with ThreadPoolExecutor(max_workers=2) as pool:
            host_f = pool.submit(self._host_intel, lex)
            page_f = pool.submit(self.page_lookup, lex.parsed.url)
            return host_f.result(), page_f.result()

    def scan(self, url: str, mode: str = "fast") -> dict:
        """Score one URL. Raises InvalidURL for input that cannot be scanned."""
        started = time.perf_counter()
        lex = extract_lexical(url)
        pred = self.predictor.predict(lex)
        p_model = pred.probability

        host = page = None
        if mode == "full":
            host, page = self._network_checks(lex)
        reasons: list[Reason] = lexical_rules(lex) + host_rules(host) + page_rules(page, lex)
        known_good = is_known_good(lex)

        # If the page redirected to another site (shorteners!), the destination
        # is what the user will actually see, so score it too and keep the worse.
        final_domain = None
        if page and page.get("final_url"):
            try:
                final_lex = extract_lexical(page["final_url"])
            except InvalidURL:
                final_lex = None
            if final_lex and final_lex.parsed.registrable_domain != lex.parsed.registrable_domain:
                final_domain = final_lex.parsed.registrable_domain
                final_p = self.predictor.predict(final_lex).probability
                # A shortened link's own text says nothing about where it goes,
                # so once we know the destination, its score replaces the
                # shortener's. For any other redirect, keep the worse of the two.
                p_model = final_p if lex.shortener else max(p_model, final_p)
                reasons += [Reason(id=f"destination:{r.id}", source=r.source, weight=r.weight,
                                   message=f"Destination: {r.message}") for r in lexical_rules(final_lex)]
                known_good = known_good and is_known_good(final_lex)

        if mode == "fast" and lex.shortener:
            reasons.append(Reason(id="shortener_hint", source="rule", weight=0.0,
                                  message="Run a deep scan to follow the short link and score its destination"))

        risk = combine(p_model, reasons, known_good)
        if known_good:
            reasons.append(Reason(id="known_good", source="allowlist", weight=0.0,
                                  message=f"{lex.parsed.registrable_domain} is a well-known site, "
                                          "so the score is capped"))

        # Model sentences explain a high probability. On a capped well-known
        # site they would contradict the verdict ("HIGH: uses the word login"
        # next to "Looks safe"), so they are left out; the raw contributions
        # are still in the feature breakdown.
        if not known_good:
            explained = {r.feature for r in reasons if r.feature}
            reasons += [r for r in model_reasons(lex, pred) if r.feature not in explained]
        reasons.sort(key=lambda r: (_SEVERITY_ORDER[r.severity], -r.weight))

        score = score_of(risk)
        return {
            "url": url,
            "normalized_url": lex.parsed.url,
            "host": lex.parsed.host,
            "unicode_host": lex.parsed.unicode_host,
            "domain": lex.parsed.registrable_domain,
            "final_domain": final_domain,
            "mode": mode,
            "score": score,
            "verdict": verdict_for(score),
            "model_probability": round(pred.probability, 4),
            "known_good": known_good,
            "reasons": [r.to_dict() for r in reasons],
            "contributions": breakdown(lex, pred),
            "features": {"lexical": lex.to_dict(), "host": host, "page": page},
            "cached": False,
            "latency_ms": round((time.perf_counter() - started) * 1000, 2),
            "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
