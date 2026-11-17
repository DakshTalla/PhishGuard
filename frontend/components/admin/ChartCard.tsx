"use client";

import { useState, type ReactNode } from "react";

// A card that can flip between a chart and the same numbers as a table, so no
// value is only reachable by hovering (and screen readers get a real table).
export default function ChartCard({ title, subtitle, chart, columns, rows, className = "" }: {
  title: string;
  subtitle?: string;
  chart: ReactNode;
  columns: string[];
  rows: (string | number)[][];
  className?: string;
}) {
  const [asTable, setAsTable] = useState(false);
  return (
    <section className={`rounded-2xl border border-line bg-surface p-5 ${className}`}>
      <div className="mb-4 flex items-start justify-between gap-4">
        <div>
          <h2 className="text-sm font-semibold">{title}</h2>
          {subtitle && <p className="mt-0.5 text-xs text-muted">{subtitle}</p>}
        </div>
        <button onClick={() => setAsTable((v) => !v)} className="flex-none text-xs text-muted hover:text-ink">
          {asTable ? "Show chart" : "Show table"}
        </button>
      </div>
      {asTable ? (
        <div className="max-h-72 overflow-auto">
          <table className="w-full text-left text-xs tabular">
            <thead className="text-muted">
              <tr>{columns.map((c) => <th key={c} className="border-b border-line py-1.5 pr-3 font-medium">{c}</th>)}</tr>
            </thead>
            <tbody>
              {rows.map((row, i) => (
                <tr key={i} className="border-b border-line/50">
                  {row.map((cell, j) => <td key={j} className="py-1.5 pr-3 text-ink-2">{cell}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        chart
      )}
    </section>
  );
}

/** Shared tooltip box for the recharts charts. */
export function TipBox({ active, payload, label, labelPrefix = "" }: {
  active?: boolean;
  payload?: ReadonlyArray<{ name?: unknown; value?: unknown; color?: string }>;
  label?: unknown;
  labelPrefix?: string;
}) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg border border-line bg-raised px-3 py-2 text-xs shadow-xl">
      <div className="mb-1 font-medium text-ink">{labelPrefix}{String(label)}</div>
      {payload.map((p, i) => (
        <div key={i} className="flex items-center gap-2 text-ink-2">
          <i className="h-2 w-2 rounded-full" style={{ background: p.color }} />
          {String(p.name)}: <span className="text-ink tabular">{String(p.value)}</span>
        </div>
      ))}
    </div>
  );
}

export const AXIS = {
  tick: { fill: "#898781", fontSize: 11 },
  axisLine: { stroke: "#383835" },
  tickLine: false,
} as const;

/** Legend labels stay in ink colour; the coloured dot beside them carries identity. */
export function legendText(value: string) {
  return <span style={{ color: "#c3c2b7" }}>{value}</span>;
}
