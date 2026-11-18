# Resume bullets

Three bullets for the PhishGuard project. Every number comes from `backend/models/metrics.json` or `docs/benchmark.json` (regenerate with `python -m phishguard.model.train` and `python -m phishguard.benchmark --full`). Latency was measured on my laptop, median of 3 runs.

**PhishGuard – phishing URL detection system** (Python, FastAPI, XGBoost, Next.js, TypeScript, Chrome Extension MV3)

- Built a phishing-URL detection system combining an XGBoost model on 34 URL features with DNS, TLS, RDAP/WHOIS and page-form checks; reached **0.934 ROC-AUC on URLs from 1,327 unseen domains** and **99.3% precision (0.33% false-positive rate) on an external 235K-URL dataset**, with per-feature SHAP explanations for every score.
- Found and fixed training-data leakage: showed that a model trained on a popular public dataset scored **98.8% in-distribution but 58.9% on realistic URLs**, then trained with a domain-grouped split and removed a hidden "www" proxy feature, raising external precision from **96.2% to 98.0%**.
- Engineered a FastAPI service and Chrome MV3 extension that warn **before a phishing page loads (0.2–0.3 s)**: **3.6 ms p50** quick scans over HTTP (cut from 12.8 ms by profiling a SQLite bottleneck), TTL/LRU caching, token-bucket rate limiting, an SSRF guard on every redirect hop, and **114 automated tests**.

## Shorter variants (if space is tight)

- Phishing URL detector (XGBoost + rules, FastAPI, Next.js, Chrome MV3): 0.934 ROC-AUC on unseen domains, 99.3% precision on an external 235K-URL set, 3.6 ms p50 API latency.
- Diagnosed dataset leakage (98.8% in-distribution vs 58.9% real-world) and fixed it with domain-grouped evaluation and feature auditing.

## Be ready to explain

- "Unseen domains": the 80/20 split is grouped by registrable domain, so no test site was seen in training (random split: 88.1% vs grouped 84.1% accuracy).
- "99.3% precision" is at the "likely phishing" threshold (score ≥ 70) on PhiUSIIL; recall there is 58.5%, because many of its phishing URLs are bare, innocent-looking domains that only a page check can catch.
- "96.2% → 98.0%" is model-only precision at probability 0.5 on PhiUSIIL, measured before and after removing the "www" proxy (study guide section 4.3).
- Latency numbers are from my laptop (`docs/benchmark.json`); the extension timing is from an end-to-end test in headless Edge.
