import { BAND_META, bandFor, timeAgo } from "@/lib/format";
import type { TopDomain } from "@/lib/types";

// Ranked list as plain HTML bars: one series, every value labelled at the tip.
export default function TopDomains({ domains }: { domains: TopDomain[] }) {
  const max = Math.max(1, ...domains.map((d) => d.scans));
  return (
    <section className="rounded-2xl border border-line bg-surface p-5">
      <h2 className="text-sm font-semibold">Top flagged domains</h2>
      <p className="mt-0.5 text-xs text-muted">Suspicious or phishing scans, by count</p>
      {domains.length === 0 ? (
        <p className="mt-6 text-sm text-ink-2">Nothing flagged yet. Scan a few URLs from the Scanner page.</p>
      ) : (
        <ul className="mt-4 space-y-3">
          {domains.map((d) => {
            const meta = BAND_META[bandFor(d.max_score)];
            return (
              <li key={d.domain} title={`${d.domain}: ${d.scans} flagged scans, max score ${d.max_score}, last seen ${timeAgo(d.last_seen)}`}>
                <div className="mb-1 flex items-center justify-between gap-3 text-xs">
                  <span className="truncate font-mono text-ink">{d.domain}</span>
                  <span className="flex flex-none items-center gap-1.5 text-ink-2">
                    <i className="h-2 w-2 rounded-full" style={{ background: meta.color }} />
                    max {d.max_score}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="h-2.5 rounded-r" style={{ width: `${(d.scans / max) * 85}%`, background: "#3987e5", minWidth: 4 }} />
                  <span className="text-xs text-ink-2 tabular">{d.scans}</span>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
