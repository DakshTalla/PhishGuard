"use client";

import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import type { Stats } from "@/lib/types";
import ChartCard, { AXIS, TipBox, legendText } from "./ChartCard";

// Verdict is a *state*, so the stack uses the status colours, each named in the legend.
const SERIES = [
  { key: "safe", label: "Safe", color: "#0ca30c" },
  { key: "suspicious", label: "Suspicious", color: "#fab219" },
  { key: "phishing", label: "Phishing", color: "#d03b3b" },
] as const;

/** Fill in days with no scans so the time axis has no gaps. */
function lastDays(perDay: Stats["per_day"], days = 14) {
  const byDay = new Map(perDay.map((d) => [d.day, d]));
  const out = [];
  for (let i = days - 1; i >= 0; i--) {
    const date = new Date(Date.now() - i * 86_400_000).toISOString().slice(0, 10);
    const row = byDay.get(date);
    out.push({ day: date.slice(5), safe: row?.safe ?? 0, suspicious: row?.suspicious ?? 0, phishing: row?.phishing ?? 0 });
  }
  return out;
}

export default function ScansPerDay({ stats }: { stats: Stats }) {
  const data = lastDays(stats.per_day);
  return (
    <ChartCard
      title="Scans per day"
      subtitle="Last 14 days, stacked by verdict"
      columns={["Day", "Safe", "Suspicious", "Phishing"]}
      rows={data.map((d) => [d.day, d.safe, d.suspicious, d.phishing])}
      chart={
        <ResponsiveContainer width="100%" height={240}>
          <BarChart data={data} margin={{ top: 4, right: 4, left: -18, bottom: 0 }}>
            <CartesianGrid vertical={false} stroke="#2c2c2a" />
            <XAxis dataKey="day" {...AXIS} interval="preserveStartEnd" />
            <YAxis allowDecimals={false} {...AXIS} axisLine={false} />
            <Tooltip cursor={{ fill: "rgba(255,255,255,0.04)" }} content={(p) => <TipBox {...p} />} />
            {/* Keep Safe -> Suspicious -> Phishing instead of the default alphabetical order. */}
            <Legend iconType="circle" iconSize={8} itemSorter={(item) => SERIES.findIndex((s) => s.key === item.dataKey)} wrapperStyle={{ fontSize: 12 }} formatter={legendText} />
            {SERIES.map((s, i) => (
              <Bar
                key={s.key}
                dataKey={s.key}
                name={s.label}
                stackId="verdict"
                fill={s.color}
                stroke="#1a1a19"
                strokeWidth={1}
                maxBarSize={24}
                isAnimationActive={false} // the dashboard refreshes every 10 s; no re-grow each time
                radius={i === SERIES.length - 1 ? [4, 4, 0, 0] : 0}
              />
            ))}
          </BarChart>
        </ResponsiveContainer>
      }
    />
  );
}
