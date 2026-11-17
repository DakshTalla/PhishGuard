"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import Card from "@/components/Card";
import FeatureBreakdown from "@/components/FeatureBreakdown";
import { HostFacts, PageFacts, UrlFacts } from "@/components/NetworkFacts";
import ReasonList from "@/components/ReasonList";
import RiskMeter from "@/components/RiskMeter";
import { ApiError, scanUrl } from "@/lib/api";
import { ms, pct } from "@/lib/format";
import type { ScanMode, ScanResult } from "@/lib/types";

const EXAMPLES = [
  { label: "Brand in subdomain", url: "http://paypal.com.secure-login.verify-account.xyz/signin" },
  { label: "Homoglyph", url: "https://аpple.com/login" },
  { label: "Typosquat", url: "http://paypa1-support.com/verify" },
  { label: "Raw IP login", url: "http://45.33.12.9/secure/login.php" },
  { label: "GitHub repo", url: "https://github.com/vercel/next.js" },
  { label: "Wikipedia", url: "https://en.wikipedia.org/wiki/Phishing" },
];

const MODES: { value: ScanMode; label: string; hint: string }[] = [
  { value: "fast", label: "Quick", hint: "URL only, milliseconds" },
  { value: "full", label: "Deep", hint: "+ DNS, TLS, WHOIS, page" },
];

type Tab = "model" | "url" | "host" | "page";

export default function Scanner() {
  const [url, setUrl] = useState("");
  const [mode, setMode] = useState<ScanMode>("fast");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [tab, setTab] = useState<Tab>("model");

  const run = useCallback(async (target: string, scanMode: ScanMode) => {
    if (!target.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const res = await scanUrl(target.trim(), scanMode);
      setResult(res);
      setTab(scanMode === "full" ? "host" : "model");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Scan failed");
    } finally {
      setLoading(false);
    }
  }, []);

  // Deep link support: /?url=...&mode=full scans on load (handy for sharing a
  // result and for screenshots). The ref stops React's development double-run
  // of effects from scanning twice.
  const deepLinked = useRef(false);
  useEffect(() => {
    if (deepLinked.current) return;
    deepLinked.current = true;
    const params = new URLSearchParams(window.location.search);
    const initial = params.get("url");
    const initialMode = params.get("mode") === "full" ? "full" : "fast";
    if (initial) {
      setUrl(initial);
      setMode(initialMode);
      run(initial, initialMode);
    }
  }, [run]);

  const tabs: { id: Tab; label: string; disabled?: boolean }[] = [
    { id: "model", label: "Model features" },
    { id: "url", label: "URL anatomy" },
    { id: "host", label: "Host", disabled: !result?.features.host },
    { id: "page", label: "Page", disabled: !result?.features.page },
  ];

  return (
    <div>
      <section className="hero-glow -mx-4 px-4 pb-10 pt-14 text-center sm:-mx-6 sm:px-6">
        <p className="text-xs font-semibold uppercase tracking-[0.2em] text-accent">Phishing &amp; malicious URL detection</p>
        <h1 className="mx-auto mt-3 max-w-2xl text-4xl font-semibold tracking-tight sm:text-5xl">Is this link safe to open?</h1>
        <p className="mx-auto mt-4 max-w-xl text-ink-2">
          A machine-learning model reads the URL, rules check the domain, certificate and page,
          and every score comes with reasons you can verify.
        </p>

        <form
          className="mx-auto mt-8 flex max-w-3xl flex-col gap-3 rounded-2xl border border-line bg-surface p-2 shadow-2xl shadow-black/40 sm:flex-row"
          onSubmit={(e) => {
            e.preventDefault();
            run(url, mode);
          }}
        >
          <label htmlFor="url" className="sr-only">URL to scan</label>
          <input
            id="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="Paste a link, e.g. http://secure-login.example.xyz/verify"
            className="min-w-0 flex-1 rounded-xl bg-transparent px-4 py-3 font-mono text-sm outline-none placeholder:text-muted focus:bg-raised/60"
            autoComplete="off"
            spellCheck={false}
          />
          <div className="flex gap-2">
            <div className="flex rounded-xl bg-raised p-1" role="radiogroup" aria-label="Scan mode">
              {MODES.map((m) => (
                <button
                  key={m.value}
                  type="button"
                  role="radio"
                  aria-checked={mode === m.value}
                  title={m.hint}
                  onClick={() => setMode(m.value)}
                  className={`rounded-lg px-3 text-sm transition-colors ${
                    mode === m.value ? "bg-surface text-ink shadow" : "text-muted hover:text-ink"
                  }`}
                >
                  {m.label}
                </button>
              ))}
            </div>
            <button
              type="submit"
              disabled={loading || !url.trim()}
              className="rounded-xl bg-accent px-5 py-3 text-sm font-semibold text-white transition hover:brightness-110 disabled:opacity-50"
            >
              {loading ? "Scanning..." : "Scan"}
            </button>
          </div>
        </form>

        <div className="mx-auto mt-4 flex max-w-3xl flex-wrap justify-center gap-2">
          {EXAMPLES.map((ex) => (
            <button
              key={ex.url}
              onClick={() => {
                setUrl(ex.url);
                run(ex.url, mode);
              }}
              className="rounded-full border border-line px-3 py-1 text-xs text-ink-2 transition-colors hover:border-accent hover:text-ink"
            >
              {ex.label}
            </button>
          ))}
        </div>
        {error && (
          <p role="alert" className="mx-auto mt-5 max-w-3xl rounded-xl border border-critical/40 bg-critical/10 px-4 py-3 text-sm text-ink">
            {error}
          </p>
        )}
      </section>

      {!result && !error && <HowItWorks />}

      {result && (
        <div key={result.scanned_at + result.normalized_url} className="rise space-y-5">
          <div className="grid gap-5 lg:grid-cols-[340px_1fr]">
            <Card>
              <RiskMeter score={result.score} />
              <dl className="mt-5 grid grid-cols-2 gap-3 text-sm">
                <Fact label="Model probability" value={pct(result.model_probability)} />
                <Fact label="Scan" value={`${result.mode === "full" ? "Deep" : "Quick"}${result.cached ? " (cached)" : ""}`} />
                <Fact label="Latency" value={ms(result.latency_ms)} />
                <Fact label="Domain" value={result.domain} />
              </dl>
              {result.final_domain && (
                <p className="mt-4 rounded-lg bg-raised px-3 py-2 text-xs text-ink-2">
                  Redirects to <span className="font-mono text-ink">{result.final_domain}</span>
                </p>
              )}
              <p className="mt-4 break-all font-mono text-[11px] leading-relaxed text-muted">{result.normalized_url}</p>
            </Card>
            <Card title="Explanation" subtitle="Rules and the model's strongest signals, most serious first">
              <ReasonList reasons={result.reasons} />
              {result.mode === "fast" && (
                <button
                  onClick={() => {
                    setMode("full");
                    run(result.url, "full");
                  }}
                  className="mt-5 text-sm font-medium text-accent hover:underline"
                >
                  Run a deep scan (DNS, TLS, domain age, page content) →
                </button>
              )}
            </Card>
          </div>

          <Card
            title="Feature breakdown"
            action={
              <div className="flex flex-wrap gap-1 rounded-xl bg-raised p-1 text-xs">
                {tabs.map((t) => (
                  <button
                    key={t.id}
                    disabled={t.disabled}
                    onClick={() => setTab(t.id)}
                    className={`rounded-lg px-3 py-1.5 transition-colors disabled:cursor-not-allowed disabled:opacity-40 ${
                      tab === t.id ? "bg-surface text-ink shadow" : "text-muted hover:text-ink"
                    }`}
                  >
                    {t.label}
                  </button>
                ))}
              </div>
            }
          >
            {tab === "model" && <FeatureBreakdown contributions={result.contributions} />}
            {tab === "url" && <UrlFacts lex={result.features.lexical} />}
            {tab === "host" && result.features.host && <HostFacts host={result.features.host} />}
            {tab === "page" && result.features.page && <PageFacts page={result.features.page} />}
          </Card>
        </div>
      )}
    </div>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0 rounded-xl bg-raised px-3 py-2">
      <dt className="text-[11px] uppercase tracking-wide text-muted">{label}</dt>
      <dd className="truncate font-medium tabular" title={value}>{value}</dd>
    </div>
  );
}

function HowItWorks() {
  const steps = [
    { n: "1", title: "Read the URL", text: "34 lexical features (length, entropy, lookalike letters, brand words, abused TLDs) go into a gradient-boosted model. Milliseconds, no network." },
    { n: "2", title: "Check the host", text: "Deep scans add DNS records, the TLS certificate and the domain's registration age from RDAP or WHOIS." },
    { n: "3", title: "Inspect the page", text: "The HTML is fetched safely and checked for password forms that post elsewhere and brand names on the wrong domain." },
  ];
  return (
    <div className="grid gap-4 sm:grid-cols-3">
      {steps.map((s) => (
        <div key={s.n} className="rounded-2xl border border-line bg-surface p-5">
          <span className="grid h-7 w-7 place-items-center rounded-full bg-accent/15 text-sm font-semibold text-accent">{s.n}</span>
          <h3 className="mt-3 font-semibold">{s.title}</h3>
          <p className="mt-1.5 text-sm text-ink-2">{s.text}</p>
        </div>
      ))}
    </div>
  );
}
