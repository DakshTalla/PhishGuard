"use client";

import { Fragment, useState } from "react";

import ReasonList from "@/components/ReasonList";
import { adminApi } from "@/lib/api";
import { BAND_META, ms, timeAgo } from "@/lib/format";
import type { HistoryRow, ScanResult, Verdict } from "@/lib/types";

const FILTERS: { value: Verdict | ""; label: string }[] = [
  { value: "", label: "All" },
  { value: "phishing", label: "Phishing" },
  { value: "suspicious", label: "Suspicious" },
  { value: "safe", label: "Safe" },
];

export default function HistoryTable({ rows, verdict, query, onVerdict, onQuery }: {
  rows: HistoryRow[];
  verdict: Verdict | "";
  query: string;
  onVerdict: (v: Verdict | "") => void;
  onQuery: (q: string) => void;
}) {
  const [openId, setOpenId] = useState<number | null>(null);
  const [detail, setDetail] = useState<ScanResult | null>(null);
  const [showAll, setShowAll] = useState(false);
  const visible = showAll ? rows : rows.slice(0, 12);

  async function toggle(id: number) {
    if (openId === id) {
      setOpenId(null);
      return;
    }
    setOpenId(id);
    setDetail(null);
    setDetail(await adminApi.scan(id).catch(() => null));
  }

  return (
    <section className="rounded-2xl border border-line bg-surface p-5">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold">Scan history</h2>
          <p className="mt-0.5 text-xs text-muted">Latest 50 scans from the web app, the extension and the API. Click a row for reasons.</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex rounded-xl bg-raised p-1 text-xs">
            {FILTERS.map((f) => (
              <button
                key={f.label}
                onClick={() => onVerdict(f.value)}
                className={`rounded-lg px-2.5 py-1 ${verdict === f.value ? "bg-surface text-ink shadow" : "text-muted hover:text-ink"}`}
              >
                {f.label}
              </button>
            ))}
          </div>
          <input
            value={query}
            onChange={(e) => onQuery(e.target.value)}
            placeholder="Filter URLs"
            aria-label="Filter URLs"
            className="w-40 rounded-xl border border-line bg-raised px-3 py-1.5 text-xs outline-none focus:border-accent"
          />
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full min-w-[720px] text-left text-sm">
          <thead className="text-xs text-muted">
            <tr className="border-b border-line">
              <th className="py-2 pr-3 font-medium">When</th>
              <th className="py-2 pr-3 font-medium">URL</th>
              <th className="py-2 pr-3 font-medium">Verdict</th>
              <th className="py-2 pr-3 text-right font-medium">Score</th>
              <th className="py-2 pr-3 font-medium">Mode</th>
              <th className="py-2 pr-3 font-medium">Source</th>
              <th className="py-2 text-right font-medium">Latency</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr><td colSpan={7} className="py-8 text-center text-ink-2">No scans match.</td></tr>
            )}
            {visible.map((row) => {
              const meta = BAND_META[row.verdict];
              return (
                <Fragment key={row.id}>
                  <tr
                    onClick={() => toggle(row.id)}
                    className="cursor-pointer border-b border-line/60 transition-colors hover:bg-raised/60"
                  >
                    <td className="whitespace-nowrap py-2 pr-3 text-xs text-muted">{timeAgo(row.created_at)}</td>
                    <td className="max-w-[340px] truncate py-2 pr-3 font-mono text-xs text-ink-2" title={row.url}>{row.url}</td>
                    <td className="py-2 pr-3">
                      <span className="inline-flex items-center gap-1.5 text-xs">
                        <i className="h-2 w-2 rounded-full" style={{ background: meta.color }} />
                        {meta.label}
                      </span>
                    </td>
                    <td className="py-2 pr-3 text-right font-semibold tabular">{row.score}</td>
                    <td className="py-2 pr-3 text-xs text-ink-2">{row.mode === "full" ? "Deep" : "Quick"}{row.cached ? " · cached" : ""}</td>
                    <td className="py-2 pr-3 text-xs capitalize text-ink-2">{row.client}</td>
                    <td className="py-2 text-right text-xs text-ink-2 tabular">{ms(row.latency_ms)}</td>
                  </tr>
                  {openId === row.id && (
                    <tr className="border-b border-line/60 bg-page/40">
                      <td colSpan={7} className="p-4">
                        {detail ? <ReasonList reasons={detail.reasons} /> : <p className="text-xs text-muted">Loading...</p>}
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
      {rows.length > 12 && (
        <button onClick={() => setShowAll((v) => !v)} className="mt-3 text-xs text-accent hover:underline">
          {showAll ? "Show fewer" : `Show all ${rows.length}`}
        </button>
      )}
    </section>
  );
}
