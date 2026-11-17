"use client";

import { useCallback, useEffect, useState } from "react";

import { ApiError, adminApi, setAdminToken } from "@/lib/api";
import { compact, ms, pct } from "@/lib/format";
import type { HistoryRow, ModelMetrics as Metrics, Stats, TopDomain, Verdict } from "@/lib/types";
import HistoryTable from "./HistoryTable";
import ModelMetrics from "./ModelMetrics";
import ScansPerDay from "./ScansPerDay";
import StatTile from "./StatTile";
import TopDomains from "./TopDomains";

const REFRESH_MS = 10_000;

export default function AdminDashboard() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [history, setHistory] = useState<HistoryRow[]>([]);
  const [top, setTop] = useState<TopDomain[]>([]);
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [verdict, setVerdict] = useState<Verdict | "">("");
  const [query, setQuery] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [needsToken, setNeedsToken] = useState(false);
  const [updated, setUpdated] = useState<Date | null>(null);

  const load = useCallback(async () => {
    try {
      const [s, h, t] = await Promise.all([
        adminApi.stats(), adminApi.history({ verdict, q: query }), adminApi.topDomains(),
      ]);
      setStats(s);
      setHistory(h);
      setTop(t);
      setError(null);
      setNeedsToken(false);
      setUpdated(new Date());
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setNeedsToken(true);
      else setError(err instanceof Error ? err.message : "Failed to load");
    }
  }, [verdict, query]);

  // Live data refreshes every 10 s; the model metrics only change on retraining.
  useEffect(() => {
    load();
    const timer = setInterval(load, REFRESH_MS);
    return () => clearInterval(timer);
  }, [load]);

  useEffect(() => {
    adminApi.metrics().then(setMetrics).catch(() => undefined);
  }, [needsToken]);

  if (needsToken) return <TokenPrompt onSave={() => { setNeedsToken(false); load(); }} />;

  return (
    <div className="space-y-5 pt-8">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
          <p className="mt-1 text-sm text-muted">Live scan activity and how well the model performs.</p>
        </div>
        <div className="flex items-center gap-3 text-xs text-muted">
          {updated && <span>Updated {updated.toLocaleTimeString()}</span>}
          <button onClick={load} className="rounded-lg border border-line px-3 py-1.5 text-ink-2 hover:border-accent hover:text-ink">Refresh</button>
        </div>
      </div>

      {error && <p role="alert" className="rounded-xl border border-critical/40 bg-critical/10 px-4 py-3 text-sm">{error}</p>}

      {stats && (
        <>
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <StatTile label="Total scans" value={compact(stats.total_scans)}
              note={Object.entries(stats.by_client).map(([k, v]) => `${v} ${k}`).join(" · ") || "none yet"} />
            <StatTile label="Flagged" value={pct(stats.flagged_rate)}
              note={`${stats.by_verdict.phishing} phishing · ${stats.by_verdict.suspicious} suspicious`} />
            <StatTile label="Quick scan latency (p50)" value={ms(stats.latency_ms.fast.p50)}
              note={`p95 ${ms(stats.latency_ms.fast.p95)} · deep p50 ${ms(stats.latency_ms.full.p50)}`} />
            <StatTile label="Cache hit rate" value={pct(stats.cache_hit_rate)} note={`${stats.cache.size} results cached in memory`} />
          </div>
          <div className="grid gap-5 lg:grid-cols-[1.6fr_1fr]">
            <ScansPerDay stats={stats} />
            <TopDomains domains={top} />
          </div>
          <HistoryTable rows={history} verdict={verdict} query={query} onVerdict={setVerdict} onQuery={setQuery} />
        </>
      )}

      {metrics && (
        <div className="pt-6">
          <h2 className="text-xl font-semibold tracking-tight">Model metrics</h2>
          <p className="mb-4 mt-1 text-sm text-muted">
            Measured by the training script on URLs from domains the model never saw. Retrain with
            <code className="mx-1 rounded bg-raised px-1.5 py-0.5 font-mono text-xs">python -m phishguard.model.train</code>.
          </p>
          <ModelMetrics metrics={metrics} />
        </div>
      )}
    </div>
  );
}

function TokenPrompt({ onSave }: { onSave: () => void }) {
  const [token, setToken] = useState("");
  return (
    <form
      className="mx-auto mt-24 max-w-sm space-y-3 rounded-2xl border border-line bg-surface p-6"
      onSubmit={(e) => {
        e.preventDefault();
        setAdminToken(token);
        onSave();
      }}
    >
      <h1 className="text-lg font-semibold">Admin token required</h1>
      <p className="text-sm text-ink-2">The API was started with PHISHGUARD_ADMIN_TOKEN. Enter it to view the dashboard.</p>
      <input type="password" value={token} onChange={(e) => setToken(e.target.value)} aria-label="Admin token"
        className="w-full rounded-xl border border-line bg-raised px-3 py-2 text-sm outline-none focus:border-accent" />
      <button className="w-full rounded-xl bg-accent px-4 py-2 text-sm font-semibold text-white">Continue</button>
    </form>
  );
}
