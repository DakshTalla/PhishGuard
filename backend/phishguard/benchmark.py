"""Measure scan latency: in-process and over HTTP, fast and (optionally) full.

Run from backend/:

    ..\\.venv\\Scripts\\python.exe -m phishguard.benchmark           # fast scans
    ..\\.venv\\Scripts\\python.exe -m phishguard.benchmark --full    # + deep scans (needs internet)

The HTTP numbers come from a private API instance started on a free port
with a temporary database and the rate limiter turned off, so the benchmark
never touches real scan history. Each measurement is repeated 3 times and the
median run is reported, because laptop timings vary with background load.
Results are written to docs/benchmark.json.
"""
from __future__ import annotations

import argparse
import json
import socket
import statistics
import tempfile
import threading
import time
from pathlib import Path

import httpx
import uvicorn

from .api import create_app
from .config import Settings
from .model.predictor import Predictor
from .scanner import Scanner

ROOT = Path(__file__).resolve().parents[2]
RUNS = 3

# Varied, realistic URL shapes. A counter is appended so every HTTP request
# is a cache miss unless we measure cache hits on purpose.
URLS = [
    "http://paypal.com.secure-login.verify-account.xyz/signin",
    "https://github.com/vercel/next.js/tree/canary/packages",
    "https://en.wikipedia.org/wiki/Phishing",
    "http://45.33.12.9/secure/login.php?session=8812",
    "https://docs-sign-in.netlify.app/?email=victim@example.com",
    "https://www.amazon.in/gp/your-account/order-history?ref_=ya_d_c_yo",
    "http://rnicrosoft-office365.com/owa/auth/logon.aspx",
    "https://news.ycombinator.com/item?id=4242",
    "https://secure-hdfcbank-kyc.top/login",
    "https://stackoverflow.com/questions/tagged/python",
]
FULL_URLS = ["https://github.com/login", "https://www.python.org/", "https://en.wikipedia.org/wiki/Main_Page"]


def vary(url: str, tag: str) -> str:
    """Add a unique query parameter so the scan cannot be a cache hit."""
    return f"{url}{'&' if '?' in url else '?'}b={tag}"


def percentiles(samples_ms: list[float]) -> dict:
    ordered = sorted(samples_ms)

    def pick(q: float) -> float:
        return ordered[min(len(ordered) - 1, int(q * len(ordered)))]

    return {"n": len(ordered), "p50": round(pick(0.50), 3), "p95": round(pick(0.95), 3),
            "p99": round(pick(0.99), 3), "mean": round(statistics.fmean(ordered), 3)}


def median_run(runs: list[dict]) -> dict:
    """The run whose p50 is the median of the runs."""
    return sorted(runs, key=lambda r: r["p50"])[len(runs) // 2]


def bench_in_process(scanner: Scanner, n: int) -> dict:
    for url in URLS:  # warm-up: first calls pay for lazy imports
        scanner.scan(url)
    runs = []
    for run_no in range(RUNS):
        samples = []
        started = time.perf_counter()
        for i in range(n):
            url = vary(URLS[i % len(URLS)], f"{run_no}-{i}")
            t = time.perf_counter()
            scanner.scan(url)
            samples.append((time.perf_counter() - t) * 1000)
        run = percentiles(samples)
        run["urls_per_second"] = round(n / (time.perf_counter() - started), 1)
        runs.append(run)
    return median_run(runs)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_server(tmp: Path) -> tuple[uvicorn.Server, threading.Thread, str]:
    """A private API instance: temp database, rate limiter effectively off."""
    settings = Settings(db_path=tmp / f"bench-{time.time_ns()}.db", rate_capacity=1e9, rate_refill_per_sec=1e9)
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(create_app(settings), host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            httpx.get(f"{base}/api/health", timeout=1)
            return server, thread, base
        except httpx.HTTPError:
            time.sleep(0.1)
    raise RuntimeError("benchmark server did not start")


def stop_server(server: uvicorn.Server, thread: threading.Thread) -> None:
    """Ask uvicorn to exit and wait, so the app's shutdown closes the database."""
    server.should_exit = True
    thread.join(timeout=10)


def time_requests(base: str, urls: list[str], mode: str) -> list[float]:
    samples = []
    with httpx.Client(base_url=base, timeout=60) as client:
        for url in urls:
            t = time.perf_counter()
            client.post("/api/scan", json={"url": url, "mode": mode}).raise_for_status()
            samples.append((time.perf_counter() - t) * 1000)
    return samples


def bench_http_fast(base: str, n: int, cached: bool) -> dict:
    time_requests(base, URLS, "fast")  # warm-up, and seeds the cache for the cached case
    runs = []
    for run_no in range(RUNS):
        urls = [URLS[i % len(URLS)] if cached else vary(URLS[i % len(URLS)], f"{run_no}-{i}") for i in range(n)]
        runs.append(percentiles(time_requests(base, urls, "fast")))
    return median_run(runs)


def bench_http_full(tmp: Path) -> dict:
    """Cold deep scans: a fresh server per run, so no host intel is cached."""
    runs = []
    for _ in range(RUNS):
        server, thread, base = start_server(tmp)
        runs.append(percentiles(time_requests(base, FULL_URLS, "full")))
        stop_server(server, thread)
    return median_run(runs)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("-n", type=int, default=500, help="requests per run (fast mode)")
    parser.add_argument("--full", action="store_true", help="also time deep scans against real sites")
    args = parser.parse_args()

    results: dict = {"measured_at": time.strftime("%Y-%m-%d %H:%M"), "runs_per_measurement": RUNS}
    print("In-process fast scans ...")
    results["in_process_fast"] = bench_in_process(Scanner(Predictor.load()), args.n)

    with tempfile.TemporaryDirectory() as tmp:
        server, thread, base = start_server(Path(tmp))
        print("HTTP fast scans (cache misses) ...")
        results["http_fast"] = bench_http_fast(base, args.n, cached=False)
        print("HTTP fast scans (cache hits) ...")
        results["http_fast_cached"] = bench_http_fast(base, args.n, cached=True)
        stop_server(server, thread)
        if args.full:
            print("HTTP deep scans against real sites, cold caches (network bound) ...")
            results["http_full_cold"] = bench_http_full(Path(tmp))

    out = ROOT / "docs" / "benchmark.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\n{'measurement':24} {'p50 ms':>8} {'p95 ms':>8} {'p99 ms':>8}")
    for key, value in results.items():
        if isinstance(value, dict):
            print(f"{key:24} {value['p50']:8.2f} {value['p95']:8.2f} {value['p99']:8.2f}")
    print(f"in-process throughput: {results['in_process_fast']['urls_per_second']} URLs/s (one thread)")
    print(f"saved {out}")


if __name__ == "__main__":
    main()
