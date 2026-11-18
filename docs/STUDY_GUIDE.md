# PhishGuard study guide

Read this before an interview. It explains what the system does, why each piece is built the way it is, which numbers you can quote and where they come from. It also covers the questions you are likely to be asked.

Contents:

1. [The problem in one minute](#1-the-problem-in-one-minute)
2. [Phishing techniques and how PhishGuard catches them](#2-phishing-techniques-and-how-phishguard-catches-them)
3. [Feature rationale (all 34 model features)](#3-feature-rationale-all-34-model-features)
4. [The data story: two datasets and two leaks](#4-the-data-story-two-datasets-and-two-leaks)
5. [The model and its explanations](#5-the-model-and-its-explanations)
6. [Rules, scoring and the known-good cap](#6-rules-scoring-and-the-known-good-cap)
7. [False positives vs false negatives](#7-false-positives-vs-false-negatives)
8. [System design decisions](#8-system-design-decisions)
9. [Numbers to quote and how to reproduce them](#9-numbers-to-quote-and-how-to-reproduce-them)
10. [Interview questions and answers](#10-interview-questions-and-answers)
11. [File-by-file walkthrough](#11-file-by-file-walkthrough)
12. [Limitations and what I would do next](#12-limitations-and-what-i-would-do-next)

---

## 1. The problem in one minute

A phishing page imitates a site you trust so that you type a secret into it: a password, a card number or an OTP. The attacker has to get you to the page (a link in an email, SMS or chat) and make it look believable. Both steps leave traces:

- **in the URL**: lookalike domains, brand names in the wrong place, random hosts, free hosting;
- **in the infrastructure**: domains a few days old, missing or fresh certificates;
- **on the page**: a login form that posts somewhere else, a page that calls itself "PayPal" on a domain that is not paypal.com.

PhishGuard checks all three layers. A machine-learning model reads the URL; hand-written rules check the rest. Everything is combined into one 0–100 score with reasons a non-expert can verify.

## 2. Phishing techniques and how PhishGuard catches them

| Technique | Example | How PhishGuard catches it | Where |
|---|---|---|---|
| Brand in the subdomain | `paypal.com.secure-login.xyz` | `brand_in_host` feature + rule (0.5); `tld_in_subdomain` | `lexical.py`, `rules.py` |
| Typosquatting | `paypa1.com`, `rnicrosoft.com`, `gooogle.com` | strict typo model: digit/letter swaps, one confusable letter, neighbour swap, doubled letter; rule (0.6) | `lookalike.py` |
| Homoglyphs / IDN | `аpple.com` (Cyrillic а) | decode punycode, map to an ASCII "skeleton", compare with brand domains; mixed-script check; rule (0.85) | `lookalike.py` |
| `@` in the authority | `http://bank.com@evil.net/` | browsers ignore everything before `@`; `has_at_symbol` + rule (0.45) | `parsing.py` |
| Raw IP host | `http://45.33.12.9/login.php` | IP in any notation (`3232235777`, `0xC0A80001`); rule (0.45) | `parsing.py` |
| Shortened links | `bit.ly/xyz` | quick scan flags it; deep scan follows the redirect and scores the **destination** | `scanner.py` |
| Free hosting abuse | `login-verify.netlify.app`, Google Forms | `free_hosting` feature + rule (0.15); never gets the known-good cap | `brands.py` |
| Hacked WordPress sites | `bakery.com/wp-content/x/login.php` | `wordpress_path`, `script_endpoint` features | `lexical.py` |
| Fake "real" domain in the path | `evil.com/www.paypal.com/login` | `domain_in_path` feature + rule (0.3) | `lexical.py` |
| Victim email pre-filled | `...?email=you@corp.com` | `has_email_in_url` + rule (0.2) | `lexical.py` |
| Cheap or abused TLDs | `.top`, `.xyz`, `.click` | `suspicious_tld` (weak on its own, 0.15) | `brands.py` |
| Fresh domains | registered 5 days ago | RDAP/WHOIS age: < 30 days (0.6), < 180 days (0.25) | `host.py` |
| Broken TLS | expired or self-signed certificate | TLS verification failure (0.35) | `host.py` |
| Credential form posts elsewhere | form `action` on another domain | `password_form_external` (0.6) | `page.py` |
| Password over plain HTTP | `http://` page with a password field | `password_over_http` (0.6) | `page.py` |
| Brand impersonation on the page | title "PayPal – Log in" on another domain, with a password field | `brand_login_page` (0.7) | `page.py` |
| Form that emails data | `<form action="mailto:...">` | `mailto_form` (0.4) | `page.py` |

**What PhishGuard does not catch** (say this before the interviewer does):
- phishing on a **compromised, innocent-looking** domain with a clean path (only page content gives it away);
- kits that **build the login form in JavaScript** (we only parse static HTML);
- **adversary-in-the-middle** kits (Evilginx-style reverse proxies) that show the real site's content;
- **OAuth consent phishing** on the real Microsoft/Google domain, QR-code phishing (no URL to click), and open redirects on trusted domains (`accounts.google.com/...continue=` is capped as known-good).

## 3. Feature rationale (all 34 model features)

All are computed by `extract_lexical()` from the URL string alone. **Why only the string for the model?** It takes microseconds, needs no network (so the extension can call it before a page loads), and is the only thing we can compute *identically* for 2020 training URLs and live traffic. Host and page facts go to the rules (section 6).

A leading `www.` is removed before measuring the host (see section 4.3).

| Feature | Why it signals phishing |
|---|---|
| `url_length`, `path_length`, `query_length` | long URLs push the real domain out of view and carry tracking/victim parameters |
| `host_length` | deceptive hosts stack words: `secure-login-paypal-verify.com` |
| `num_dots_host` | extra labels fake a familiar domain at the start of the host |
| `num_hyphens_host` | `secure-login-bank` style names |
| `num_digits_host`, `digit_ratio_url` | machine-generated names and IDs |
| `subdomain_depth` | labels left of the registrable domain; `www` is not counted |
| `domain_entropy` | randomness of the name the attacker bought (`xk29qf.top`) |
| `url_entropy` | random tokens, encoded payloads |
| `path_depth`, `num_query_params` | kits live deep in hacked sites and carry many parameters |
| `num_special_chars`, `num_percent_encoded` | `%xx` escapes hide words from filters |
| `longest_token_length` | long random strings (session IDs, base64) |
| `suspicious_word_count` | `login`, `verify`, `account`, `secure`, ... (Garera et al. 2007, extended) |
| `is_https` | weak today (most phishing has TLS) but HTTP still correlates |
| `has_ip_host`, `has_port` | real businesses use domain names and standard ports |
| `has_at_symbol` | the userinfo trick |
| `has_double_slash_path` | open-redirect style paths |
| `has_email_in_url` | kits pre-fill the victim's address |
| `is_punycode`, `has_non_ascii` | IDN lookalikes |
| `suspicious_tld` | abused TLD list (Spamhaus, Interisle) |
| `is_shortener` | destination hidden |
| `free_hosting` | anyone can publish there, and it comes with a free certificate |
| `tld_in_subdomain` | `paypal.com.evil.xyz`, `runescape.com-en.ru` |
| `brand_in_host` | brand keyword in a host the brand does not own |
| `brand_in_path` | brand keyword in the path of an unrelated site |
| `domain_in_path` | another site's domain name in the path to look legitimate |
| `script_endpoint` | path ends in `.php/.asp/...`: the kit's form handler |
| `wordpress_path` | `wp-content/`, `wp-admin/`: kit uploaded to a hacked WordPress site |

The last three were added **after error analysis on the training part only**. In training data, `domain_in_path` appears in 0.2% of legitimate URLs vs 3.8% of phishing ones, `script_endpoint` in 3.4% vs 18.2%, and `wordpress_path` in 0.1% vs 9.7%. Adding them raised grouped-CV F1 from 0.875 to 0.888 for the same depth-6 model (0.890 at the depth 4 finally chosen).

**Brand matching is length-aware** (`brand_matches` in `lexical.py`): brands with 6+ letters match anywhere in a token (`mypaypal`); 4–5 letters only at the start (`appleid`, `hdfcbank`); shorter ones only as a whole token (`sbi`). This is why `pineapple` is not Apple and `purchase` is not Chase.

**Typo detection is deliberately strict** (`is_typo_of` in `lookalike.py`). Plain edit distance flags `cloud` as a typo of `icloud` and `finance` as a typo of `binance`, which would hit thousands of honest sites. Only mistakes a victim would not notice count: one visually confusable swap (`l`↔`i`, `o`↔`0`, `m`↔`n`), two neighbouring letters swapped, or a doubled or un-doubled letter.

## 4. The data story: two datasets and two leaks

This section is the best interview material in the project. It shows that I looked at the data before trusting a metric.

### 4.1 Two datasets

| | Mendeley (Hannousse & Yahiouche, 2020) | PhiUSIIL (Prasad & Chandra, 2024) |
|---|---|---|
| Size | 11,430 URLs, 50/50 | 235,795 URLs |
| Legitimate URLs | real deep links (Wikipedia articles, PDFs, blog posts), 44% https, 67% `www.` | **100% bare `https://www.` homepages, 0% with a path** |
| Role here | training + held-out test | external test + leakage experiment |
| Gotcha | – | `label = 1` means **legitimate** (flipped in `dataset.py`) |

### 4.2 Leak 1: the bigger dataset teaches URL shape, not phishing

If every legitimate URL is `https://www.something.com` with no path, a model learns "has a path, or uses http → phishing". It scores almost perfectly on its own test split and is useless in a browser, where most legitimate URLs have paths. `train.py` measures this:

- trained on PhiUSIIL, tested on PhiUSIIL: **98.8%** accuracy;
- same model tested on Mendeley: **58.9%** accuracy with an **81% false-positive rate**;
- its most important feature: **"Uses HTTPS"**.

So the model is trained on Mendeley, and PhiUSIIL is only used to test it from the outside.

### 4.3 Leak 2: "www" sneaking in through another feature

I first excluded `www` as a feature because it reflects how the legitimate URLs were crawled (67% of legitimate vs 21% of phishing), not a phishing technique. But a smoke test scored `github.com/vercel/next.js` at **0.80**. The TreeSHAP breakdown showed `num_dots_host = 1` adding +1.38 log-odds: "host has exactly one dot" was just "no `www.`" in disguise.

Fix: strip a leading `www.` before measuring any host feature (same site, same features). Measured during development:

| | before | after |
|---|---|---|
| grouped CV F1 | 0.890 | 0.870 |
| grouped CV ROC-AUC | 0.956 | 0.946 |
| external precision (PhiUSIIL, model at 0.5) | 96.2% | **98.0%** |
| `github.com/vercel/next.js` probability | 0.80 | 0.39 |

The in-dataset numbers went **down** and the out-of-dataset numbers went **up**. That is the signature of removing a shortcut. A regression test (`test_www_does_not_change_host_features`) keeps it fixed.

### 4.4 Grouped split

URLs from one site are very similar, so a random split puts `site.com/a` in train and `site.com/b` in test, and the model is graded on sites it has already seen. `train.py` uses `GroupShuffleSplit` by **registrable domain** (`paypal-x.netlify.app` and `abc.netlify.app` both group under `netlify.app`) and asserts that no domain appears on both sides. Cost of honesty, measured: a random split reports **88.1%** accuracy (ROC-AUC 0.955) instead of **84.1%** (0.934).

Also: URLs are normalised with the same `parse_url()` the API uses, exact duplicates are removed, and URLs labelled both ways are dropped.

### 4.5 Error analysis showed the cost of grouping

Most test-set false positives were **legitimate personal blogs on tumblr.com and wordpress.com**. Grouping put those whole platforms in the test set, while training was full of phishing on blogspot.com and appspot.com. So the model learned "subdomain on a blogging platform = phishing". I did **not** tune lists on the test set to hide this; it is reported and discussed instead.

## 5. The model and its explanations

- **XGBoost**, 400 trees, depth 4, learning rate 0.05, row and column subsampling 0.9. Depth was picked by grouped CV on the training part: depth 4 and 6 tied (F1 0.890 vs 0.888), so the simpler model won.
- **Why trees:** the features are a mix of counts, ratios and flags with thresholds and interactions ("long URL *and* suspicious words"). Boosted trees handle that without scaling and are strong on tabular data of this size (11k rows).
- **Baseline:** logistic regression (scaled) reaches ROC-AUC 0.908 vs XGBoost 0.934. The gap shows the trees earn their complexity, but not by a huge margin. Say so; it is honest.
- **Why not a deep model on raw characters?** It needs far more data, hides why it decided, and would learn this dataset's quirks just as easily.
- **Saved as XGBoost JSON**, not pickle: loading a pickle can execute code, so a swapped model file would be remote code execution. `Predictor` also refuses a model whose feature list differs from the code.
- **Explanations (TreeSHAP):** `booster.predict(pred_contribs=True)` splits each prediction into one additive contribution per feature plus a bias. Summed and passed through a sigmoid, they give exactly the predicted probability (tested in `test_model.py`). The UI shows all contributions as a diverging bar chart (red raises risk, blue lowers it).
- **Readable reasons:** `explain.py` turns the biggest positive contributions (≥ 0.4 log-odds, at most 4) into sentences, but only when the value is unusual in the risky direction. A tree can give "34 characters long" a positive push through an interaction; telling a user "risky: the URL is short" would be confusing. The raw number is still in the breakdown.

## 6. Rules, scoring and the known-good cap

**Why rules next to a model?**
1. Some attacks are too rare in public data to learn (a homoglyph of one specific brand) but are certain once detected.
2. Host and page facts (domain age, password forms) cannot be computed for years-old training URLs, so no model can be trained on them here.
3. A rule is one readable sentence, which is what a user acts on.

Each rule has a weight in [0, 1]: "on its own, how sure would this make me?" They are expert judgement, written down in one file (`rules.py`), and their combined effect is measured on the test set ("model + rules" rows).

**Noisy-OR combination** (`scoring.py`):

```
risk = 1 − (1 − p_model) × (1 − w₁) × (1 − w₂) × ...
```

Read it as: the chance that the model *and* every fired rule are all wrong is the product of their individual chances of being wrong. Properties: one strong signal is enough (a homoglyph alone gives ≥ 85), more evidence only raises the risk, and it never exceeds 100. **Weakness:** double counting when two signals are really the same evidence (the model's `has_ip_host` and the `ip_host` rule). I limit it by keeping strong weights for things the model rarely saw. On this test set the rules barely move ROC-AUC (0.934 → 0.936), which is expected: they target rare attacks and network facts that this dataset does not contain.

**Known-good cap:** a URL on a curated list of popular domains gets at most 10. The exception is platforms where strangers publish content (sites.google.com, docs.google.com, *.github.io, netlify.app, ...): they never get the cap. In those cases, model sentences are left out of "Why this score" so that a red reason never sits next to a "Looks safe" verdict.

**Bands:** < 40 safe, 40–69 suspicious, ≥ 70 likely phishing. The extension warns at 70 by default (user-adjustable).

## 7. False positives vs false negatives

- **False negative** (phishing scored safe): the user may lose credentials or money. This is the expensive one per event.
- **False positive** (safe site flagged): annoying, and worse, it teaches users to click "continue anyway", so the next real warning is ignored (*alert fatigue*). An interstitial that is wrong too often is worse than no interstitial.

That is why there are two thresholds. The **dashboard and scanner** label from 40 ("suspicious": 91.8% recall, 21.3% FPR) because a human is looking anyway. The **extension** interrupts only from 70 (89.5% precision, 72.1% recall, 6.5% FPR).

**The base-rate fallacy** (a favourite interview question). The test set is about 44% phishing. Real browsing is far below 1%. Precision depends on prevalence:

```
precision = recall × p / (recall × p + FPR × (1 − p))
```

Using the measured recall and FPR:

| Flag at | Test precision | Precision if 10% of URLs were phishing | if 1% were |
|---|---|---|---|
| 40 | 77.0% | 32% | 4% |
| 70 | 89.5% | 55% | 10% |
| 90 | 96.9% | 82% | 29% |

So at 1% prevalence, 9 of 10 warnings at threshold 70 would be false alarms *if every URL were scored blindly*. Real systems survive this because most browsing goes to a small set of popular domains (the known-good cap removes them), users can allowlist sites, and reputation feeds and deep checks add evidence. Mentioning this shows you understand why lab accuracy is not product accuracy.

On the external PhiUSIIL set (135K legitimate homepages) the false-positive rate at 70 was only 0.33%. Legitimate homepages are the easy case; deep links are harder.

## 8. System design decisions

**Quick vs deep scan.** Quick = lexical + model + lexical rules, 1.5 ms in-process, no network. Deep adds DNS, TLS, RDAP/WHOIS and the page, ~0.6 s cold. The extension needs an answer before the page loads, so it uses quick. A human asking "is this safe?" can wait for deep.

**Parallel network checks with budgets.** DNS (shared 2.5 s budget over A/AAAA/MX/NS), TLS (3 s), domain age (4 s) and the page fetch (6 s total, 1 MB, 5 redirects) run in a thread pool, so latency is the slowest one, not the sum. Every lookup returns a dict with an `error` field instead of raising, so one failure never kills a scan.

**RDAP before WHOIS.** RDAP is WHOIS's successor: JSON over HTTPS with a standard schema, and ICANN made it the required protocol for gTLDs in January 2025. Port-43 WHOIS returns free text that differs per registry, so it is only a fallback (many country TLDs still need it).

**Domain age is a strong but imperfect signal.** Most phishing domains are used within days of registration, before blocklists catch up. But a new startup is also new, and hacked old domains are old. So it is a 0.6 rule, not a verdict. An old domain is shown as context with weight 0.

**HTTPS is not a safety signal.** Free certificates (Let's Encrypt) mean most phishing sites have valid TLS. A *failed* certificate is suspicious (0.35); a valid one is only context. Note that Python does not fetch missing intermediate certificates the way browsers do, so a misconfigured but honest server can fail here. This is a known false-positive source.

**SSRF guard.** The server fetches URLs strangers type. Without a guard, `http://169.254.169.254/` (cloud metadata) or `http://localhost:8000/admin` would make *our* server read internal resources (OWASP A10:2021). `netguard.resolve_public()` resolves the host and refuses it if **any** address is not globally routable (private, loopback, link-local, carrier-NAT, IPv4-mapped IPv6). Redirects are followed by hand so every hop is checked. **Residual risk, DNS rebinding:** httpx resolves the name again when connecting, so a malicious DNS server could answer differently the second time. The TLS check avoids this by connecting to the exact IP it validated. Full fix: pin the resolved IP for the HTTP request, or use an egress proxy that enforces the policy.

**Caching.** Two TTL+LRU caches (my own 40-line class, thread-safe with a lock): scan results keyed by `mode:normalised-url` for 10 minutes, and host intel keyed by host for 6 hours (many URLs share a host, and WHOIS servers rate-limit). Normalisation (lower-case host, drop `#fragment`, punycode) makes `EXAMPLE.org/a#x` and `example.org/a` one cache entry.

**Rate limiting.** A token bucket per client IP: 30 tokens burst, refilling at 0.5/s (30/minute). A deep scan costs 5 because it makes outbound DNS, TLS, WHOIS and HTTP calls; without that, one client could use our server to hammer third parties. A rejected request gets `429` with `Retry-After`, and `demo_scans.py` shows a well-behaved client honouring it. A token bucket allows bursts (opening ten tabs) while capping the long-run rate; a fixed window allows double bursts at window edges. Behind a reverse proxy you would read the client IP from `X-Forwarded-For`, and only from trusted proxies.

**The SQLite performance bug (a good story).** The benchmark showed that even a **cache hit** took 8–9 ms over HTTP, and timing each piece showed `store.record` at **7.3 ms**. Cause: a new connection per call. In WAL mode, closing the last connection checkpoints and deletes the WAL file, so every scan paid for that. My first guess (fsync, fixed with `synchronous=NORMAL`) helped only ~0.7 ms, which is why you measure instead of guessing. Fix: one long-lived connection shared by FastAPI's worker threads behind a lock. Quick-scan p50 over HTTP went **12.8 → 3.6 ms**, cache hits 8.1 → 1.2 ms, and p99 215 → 7.6 ms.

**Sync endpoints on purpose.** DNS, TLS and WHOIS libraries block. FastAPI runs plain `def` endpoints in a thread pool, so they do not freeze the event loop. `async def` with blocking calls inside would stall every request.

**Extension under Manifest V3.** MV3 removed blocking `webRequest` for normal extensions, so an extension cannot pause a request while it asks a server. PhishGuard starts a quick scan on `webNavigation.onBeforeNavigate` and, if risky, replaces the tab's URL with its own warning page. The scan (~4 ms) usually beats DNS + TLS + first byte; measured end to end in headless Edge, the warning appeared 0.2–0.3 s after navigation started (polling every 0.2 s). Details:
- in-memory cache plus in-flight de-duplication (`onBeforeNavigate` and `onCommitted` share one request);
- shortened links: skip the pre-check and score the destination on `onCommitted`, after Chrome has followed the redirect;
- **fail open**: if the API is down the page loads and the badge shows `?`. Fail closed would make the whole web unusable whenever the local backend is off;
- "Continue anyway" bypasses the host until the browser closes (`chrome.storage.session`); "Always trust" adds the domain to the allowlist in `chrome.storage.sync`;
- an allowlist entry covers subdomains (`a.example.com`) but not lookalike suffixes (`badexample.com`, `example.com.evil.xyz`), which is unit-tested;
- alternative considered: `declarativeNetRequest` dynamic rules for domains already flagged. They would block repeat visits at the network layer, but add rule bookkeeping. Good next step.

**Privacy.** The extension sends every visited URL to the API. That is acceptable for a *local* backend you run yourself. A hosted service should not receive full URLs: Google Safe Browsing's Update API checks **hashed URL prefixes** locally and only asks the server about partial hash matches. Also, query strings can contain tokens and email addresses; we never log them anywhere except the local SQLite history.

**XSS from scanned content.** Hostnames, page titles and URLs are attacker-controlled and are shown in our UIs. React escapes text, and the extension uses `textContent` (never `innerHTML`) for API text.

## 9. Numbers to quote and how to reproduce them

| Claim | Value | Reproduce |
|---|---|---|
| ROC-AUC on unseen domains | 0.934 | `python -m phishguard.model.train` → `metrics.json` `test.model` |
| Precision / recall / FPR at score ≥ 70 | 89.5% / 72.1% / 6.5% | `test.system_phishing` |
| Grouped 5-fold CV | F1 0.870 ± 0.022, ROC-AUC 0.946 ± 0.019 | `cv` |
| Logistic-regression baseline ROC-AUC | 0.908 | `test.baseline_logreg` |
| External PhiUSIIL (234,685 URLs) | ROC-AUC 0.930; at 70: 99.3% precision, 0.33% FPR, 58.5% recall | `external.phiusiil` |
| Leakage experiment | 98.8% in-distribution → 58.9% on Mendeley, 81% FPR | `leakage_experiment` |
| Random vs grouped split | 88.1% vs 84.1% accuracy | `random_split_comparison` |
| Quick scan latency | 1.5 ms in-process (~640/s/thread), 3.6 ms p50 over HTTP | `python -m phishguard.benchmark` → `docs/benchmark.json` |
| Cache hit | 1.2 ms p50 | same |
| Deep scan, cold | 623 ms p50 (3 real sites) | `--full` |
| SQLite fix | 12.8 → 3.6 ms p50 | before/after runs during development |
| Extension warning | 0.2–0.3 s after navigation starts | headless Edge + DevTools protocol (development) |
| Tests | 114 (104 backend, 6 extension, 4 frontend) | see README |

Benchmarks vary with laptop load, so each value is the median of 3 runs. Say "on my laptop".

## 10. Interview questions and answers

**1. Walk me through a scan.** The URL is normalised (scheme added, host lower-cased and punycoded, fragment dropped) and split with the Public Suffix List. 34 lexical features go into XGBoost, which returns a probability plus per-feature TreeSHAP contributions. Lexical rules check lookalikes, brand misuse, IPs, the `@` trick and so on. A deep scan also runs DNS, TLS, RDAP/WHOIS and a page fetch in parallel behind an SSRF guard, and host and page rules fire on those facts. Noisy-OR combines the model and rule weights into 0–100, well-known domains are capped, and the result (score, verdict, reasons, contributions) is cached and stored in SQLite.

**2. Why is the model trained only on URL features?** They are free to compute, work before the page loads, and can be computed identically for old training URLs and live traffic. Domain age or page content for 2020 URLs cannot be recomputed today, since those sites are gone or changed hands, so a model trained on them would see different inputs in production (train/serve skew).

**3. How did you split the data?** 80/20 grouped by registrable domain, with an assertion that no domain is on both sides, plus 5-fold `StratifiedGroupKFold` on the training part. A random split would have reported 88.1% instead of 84.1%, because URLs of the same site leak across.

**4. What is data leakage? Give an example from this project.** Information in training that will not be available, or will not behave the same, in real use, making evaluation optimistic. Example 1: PhiUSIIL's legitimate URLs are all bare `https://www.` homepages, so "uses HTTPS" became the top feature (98.8% → 58.9% out of distribution). Example 2: `num_dots_host = 1` was a proxy for "no www", a crawling artefact; I found it through a SHAP breakdown of a wrong prediction.

**5. Why XGBoost over logistic regression or a neural net?** Mixed-type tabular features with thresholds and interactions suit boosted trees; ROC-AUC 0.934 vs 0.908 for logistic regression. A character-level neural net needs more data, is harder to explain and would learn dataset quirks just as easily. Trees also give exact TreeSHAP explanations cheaply.

**6. How do the explanations work?** TreeSHAP splits a tree ensemble's output into additive per-feature contributions in log-odds; they sum (with a bias) to the model's log-odds. I show all of them as a diverging chart, and turn the biggest risk-raising ones into sentences only when the feature value is unusual in the risky direction.

**7. Why both a model and rules? Why not just the model?** Rules cover attacks too rare to learn (homoglyphs of a specific brand) and facts that cannot be in training data (domain age, page forms). They are also auditable sentences. The model covers the fuzzy statistical patterns that rules miss.

**8. Explain noisy-OR. What is wrong with it?** Risk = 1 minus the product of each signal's chance of being wrong. It is monotone, bounded and lets one strong signal dominate. It assumes signals are independent, so it double-counts correlated ones (a model feature and a rule about the same thing). Fixes: lower the rule weight when the model already covers it, or learn the weights with logistic regression on labelled host and page data, if such data existed.

**9. How did you pick 40 and 70?** 70 is where the extension interrupts: 89.5% precision and 6.5% FPR on the test set. Interrupting is costly, so precision matters. 40 is the "suspicious" label for a human looking at the scanner: 91.8% recall. The threshold table on the dashboard shows the whole trade-off, so the choice is visible and adjustable.

**10. Precision is 89.5%. Would it be that in production?** No, because of the base rate. With 1% phishing, the same recall and FPR give about 10% precision. Popular-domain caps, user allowlists, deep checks and reputation feeds are what make real systems usable.

**11. How do you detect homoglyph domains?** Decode punycode to Unicode, map each character through a confusables table (a subset of Unicode UTS #39) to an ASCII "skeleton", and compare with brand domains and keywords. Also flag labels that mix Latin, Cyrillic or Greek, as Chrome does when deciding to show punycode. `аpple.com` → skeleton `apple.com` → homoglyph of apple.com.

**12. How do you avoid typosquat false positives?** Plain edit distance 1 flags `cloud` (icloud) and `finance` (binance). I count only typos a victim would not notice: confusable swaps (`l/i`, `o/0`, `rn→m`), neighbour transpositions and doubled letters, and only for brands of 5+ letters. There are tests for both the attacks and the false alarms.

**13. What is SSRF and how did you prevent it?** Server-side request forgery: tricking a server into making requests to internal addresses. I resolve the host and refuse it if any address is not globally routable, re-check every redirect hop by following redirects manually, and connect TLS to the validated IP. Residual risk: DNS rebinding for the HTTP fetch; fix with IP pinning or an egress proxy.

**14. Why is HTTPS not proof of safety?** Certificates are free and automatic, and most phishing sites have them. A certificate proves you are talking to whoever controls the domain, not that the domain is honest.

**15. RDAP vs WHOIS?** RDAP is structured JSON over HTTPS and the ICANN-required protocol for gTLDs since January 2025. WHOIS is free text over port 43 with per-registry formats. I try RDAP first and fall back to WHOIS for TLDs that lack RDAP.

**16. How does the extension warn *before* the page loads?** MV3 forbids blocking `webRequest`, so on `onBeforeNavigate` I start a ~4 ms scan and, if risky, `tabs.update()` the tab to the warning page. It usually wins the race against DNS + TLS + first byte; repeat visits hit an in-memory cache. Shortened links are checked at `onCommitted`, after the redirect.

**17. Fail open or fail closed?** Open: if the local API is down, pages load and the badge shows `?`. For a security product protecting a whole company you might fail closed on high-risk categories. For a browser assistant, breaking the web is worse.

**18. Explain your cache. How would you invalidate it?** TTL + LRU in an `OrderedDict` with a lock; keys are mode plus normalised URL. TTL bounds staleness (10 minutes for results, 6 hours for host intel). Retraining or changing rules should clear it; in a multi-instance deployment I would move it to Redis with a model-version prefix in the key.

**19. Token bucket vs fixed window?** A token bucket allows a burst up to its capacity, then a steady rate; a fixed window allows up to 2× the limit around window boundaries. Costs differ per request type, so expensive deep scans spend 5 tokens. Memory is bounded by forgetting buckets that have refilled.

**20. Tell me about a performance problem you solved.** The SQLite story in section 8: a cache hit still cost 8–9 ms. I timed each step, found 7.3 ms in the history write, tried fsync first (small gain), then found the real cause (per-call connections forcing WAL checkpoints) and shared one locked connection. p50 went from 12.8 to 3.6 ms. Lesson: measure each layer before optimising.

**21. Why are your FastAPI endpoints not async?** The DNS, TLS and WHOIS libraries block. In `async def` they would block the event loop for every request. Plain `def` endpoints run in FastAPI's thread pool.

**22. How would you scale this to millions of users?** Keep quick scans stateless behind a load balancer; the model is a 662 KB JSON file and scans are CPU-bound, so throughput scales with cores (~640 URLs/s per core in-process). Move caches to Redis, history to Postgres or a log pipeline, and run deep scans through a queue with workers behind an egress proxy. Put the verdict for popular domains in a CDN-cached reputation list, and switch the client protocol to hash prefixes for privacy.

**23. How would you keep the model current?** Phishing drifts quickly (new TLDs, platforms, kits). Retrain on fresh labelled feeds (PhishTank, OpenPhish, plus Tranco-ranked URLs for legitimate ones), evaluate on a time-held-out month, and watch production signals: score distribution shift, the user override rate on warnings, and allowlist additions.

**24. How would an attacker evade your model?** Short, clean paths on an aged, innocent-looking domain with no brand word in the URL; JavaScript-rendered forms; reverse-proxy kits; hosting on a known-good domain (Google Forms, SharePoint). Mitigations: deep page analysis with a headless browser in a sandbox, visual similarity to brand login pages, and reputation feeds.

**25. How do you test network-dependent code?** Network lookups are injected into `Scanner`, so API tests pass fakes. `socket.getaddrinfo` is monkeypatched to test the SSRF guard; HTML analysis is tested on fixture pages; RDAP and WHOIS are monkeypatched to test fallback and errors. All 104 backend tests run offline in about a second. The extension was also tested end to end in headless Edge.

**26. Why did you write your own cache and rate limiter?** Each is about 40 lines, fully tested with a fake clock, and I can explain every line. In production I would use Redis-backed equivalents so several API instances share state.

**27. What would you do differently?** Collect a fresher dataset with real deep-link legitimate URLs from a popularity list, evaluate on a time split, learn the rule weights instead of hand-setting them, and add a sandboxed headless browser for JavaScript-built pages.

**28. Why store the model as JSON, and why pin dataset hashes?** Unpickling runs code, so a tampered pickle would be code execution; JSON is data. Pinned SHA-256 hashes make a changed or tampered download fail loudly instead of silently changing the model. Zip extraction takes one named member to avoid zip-slip path traversal.

## 11. File-by-file walkthrough

### Root
- `start.ps1` / `start.bat`: one-command setup and launch (venv, packages, optional retrain, web build, two server windows, health wait). `start.bat` only bypasses the execution policy for this one process.
- `stop.ps1`: stops whatever listens on ports 8000 and 3100.
- `.gitattributes`: LF in the repo, CRLF for `.bat`/`.ps1` (cmd.exe misreads LF batch files).
- `.gitignore`: venv, caches, downloaded data, the local scan database, Node build output.

### backend/phishguard
- `__init__.py`: package docstring with the reading order.
- `config.py`: `Settings` dataclass read from `PHISHGUARD_*` environment variables.
- `features/parsing.py`: `parse_url()` validates and normalises input (rejects `javascript:`/`file:`, adds `https://`, punycode, drops the fragment) and splits the host with the bundled Public Suffix List snapshot. It detects IPs in any notation and the userinfo trick.
- `features/brands.py`: plain data: brand → real domains, known-good domains, user-content platforms, shorteners, abused TLDs, suspicious words, plus two suffix-matching helpers.
- `features/lookalike.py`: confusables skeleton, mixed-script check, the strict `is_typo_of`, and `find_lookalike()`.
- `features/lexical.py`: the 34 model features (`FEATURE_NAMES`) and `LexicalResult` (features plus facts such as the brands found).
- `features/netguard.py`: `is_public_ip()` and `resolve_public()`, the SSRF guard.
- `features/host.py`: DNS records with a shared budget, a TLS handshake to the validated IP, domain age via RDAP then WHOIS, and `gather_host_intel()` running them in parallel.
- `features/page.py`: `fetch_page()` (manual redirects, size and time limits, SSRF re-check per hop) and `analyze_html()` (forms, password fields, mailto actions, meta refresh, brand in title).
- `model/dataset.py`: loads both CSVs as (url, label=1 for phishing), flips PhiUSIIL's labels, removes duplicates and conflicts.
- `model/train.py`: features, grouped split, grouped CV, random-split comparison, XGBoost plus baseline, test and system metrics, external test, leakage experiment; writes `model.json` and `metrics.json`.
- `model/predictor.py`: loads the JSON model and returns probability plus TreeSHAP contributions.
- `model/explain.py`: labels for every feature, the full breakdown, and plausibility-filtered model sentences.
- `rules.py`: the `Reason` dataclass and lexical, host and page rules with weights.
- `scoring.py`: noisy-OR, the known-good cap and verdict bands.
- `scanner.py`: the pipeline; injects network lookups, caches host intel, unwraps redirects, orders reasons.
- `cache.py`: thread-safe TTL + LRU cache.
- `ratelimit.py`: per-client token bucket with bounded memory.
- `store.py`: SQLite history on one locked WAL connection, plus the dashboard queries.
- `api.py`: `create_app()` factory: CORS, rate limit, cache, scan and admin endpoints, optional admin token, closes the store on shutdown.
- `main.py`: `app = create_app()` for uvicorn (kept separate so tests can import the factory without loading anything).
- `benchmark.py`: in-process and HTTP latency on a private server instance, median of 3 runs, writes `docs/benchmark.json`.

### backend (other)
- `scripts/download_datasets.py`: downloads and verifies both datasets, extracting one zip member by name.
- `scripts/demo_scans.py`: fills the dashboard; synthetic phishing URLs are quick-scanned only; honours `Retry-After`.
- `models/model.json`, `models/metrics.json`: the committed model and its measurements.
- `tests/`: `conftest.py` (model fixture, fake DNS), plus test files for parsing, lexical, lookalike, network features, rules and scoring, cache and rate limiting, the model, and the API end to end.
- `requirements.txt`, `pytest.ini`.

### extension
- `manifest.json`: MV3; permissions `webNavigation`, `storage`, `activeTab`; host access only to `localhost`/`127.0.0.1`.
- `background.js`: service worker: navigation checks, cache and in-flight de-duplication, badge, redirect to the warning page, message handlers for leave / proceed / trust.
- `lib/core.js`: pure helpers (bands, allowlist matching and normalisation, which URLs to scan, reason ordering), unit-tested.
- `lib/api.js`: settings in `chrome.storage.sync`, and `scan()` with a timeout that fails open.
- `lib/ui.js`: score ring and XSS-safe reason list. `lib/demo.js`: sample data for `?demo=1` screenshots.
- `warning.html/.css/.js`: the interstitial. `popup.html/.css/.js`: toolbar popup with deep scan and trust. `options.html/.js`: threshold, API address, allowlist. `styles.css`: shared tokens.
- `tools/make_icons.py`: draws the PNG icons with the standard library. `tests/core.test.js`: 6 `node --test` tests. `package.json`: only for `npm test`.

### frontend
- `app/layout.tsx`: shell with `Nav`. `app/page.tsx`: the scanner. `app/admin/page.tsx`: the dashboard. `app/globals.css`: design tokens (validated dark palette). `app/icon.svg`: favicon.
- `components/Scanner.tsx`: input, quick/deep toggle, examples, deep-link `?url=`, result layout and tabs.
- `components/RiskMeter.tsx`: animated semicircle gauge (requestAnimationFrame, respects reduced motion).
- `components/ReasonList.tsx`, `FeatureBreakdown.tsx` (diverging contribution bars), `NetworkFacts.tsx` (URL, host and page facts), `Card.tsx`, `Nav.tsx` (API health dot).
- `components/admin/`: `AdminDashboard.tsx` (loading, 10 s refresh, token prompt), `StatTile.tsx`, `ScansPerDay.tsx` (stacked by verdict), `TopDomains.tsx`, `HistoryTable.tsx` (filters, expandable reasons), `ModelMetrics.tsx` (PR curve, score separation, confusion matrix, threshold table, importance, leakage callout), `ChartCard.tsx` (chart ⇄ table toggle, tooltip, axis style).
- `lib/api.ts`: fetch helpers and admin token in `sessionStorage`. `lib/types.ts`: response types. `lib/format.ts` + `format.test.ts`: formatting helpers and their tests.
- `next.config.ts`, `postcss.config.mjs` (Tailwind v4), `tsconfig.json`, `package.json`.

## 12. Limitations and what I would do next

1. **Fresher, larger, time-split data.** Build a dataset from current phishing feeds plus legitimate deep links sampled from a popularity list (Tranco), and evaluate on a later month than training.
2. **Learn the rule weights** with a calibrated model on host and page features collected at scan time, instead of expert weights.
3. **Sandboxed headless-browser analysis** for JavaScript-built forms, plus visual similarity to brand login pages.
4. **`declarativeNetRequest` rules** so repeat visits to flagged domains are blocked at the network layer.
5. **Hash-prefix privacy protocol** for a hosted version, and DNS-rebinding-proof fetching (IP pinning or an egress proxy).
6. **Production observability:** warning override rate, score-distribution drift and per-rule firing rates as model-health signals.
