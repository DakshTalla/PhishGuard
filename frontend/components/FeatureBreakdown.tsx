"use client";

import { useState } from "react";

import { featureValue } from "@/lib/format";
import type { Contribution } from "@/lib/types";

// Diverging bars around zero: red pushes towards phishing, blue towards
// legitimate (the blue<->red diverging pair; grey centre line = no effect).
// Values are the model's per-feature contributions in log-odds (TreeSHAP).
const UP = "var(--color-critical)";
const DOWN = "var(--color-accent)";

export default function FeatureBreakdown({ contributions }: { contributions: Contribution[] }) {
  const [showAll, setShowAll] = useState(false);
  const rows = showAll ? contributions : contributions.slice(0, 12);
  const max = Math.max(1, ...contributions.map((c) => Math.abs(c.contribution)));

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-4 text-xs text-ink-2">
        <span className="flex items-center gap-1.5"><i className="h-2.5 w-2.5 rounded-sm" style={{ background: UP }} /> raises risk</span>
        <span className="flex items-center gap-1.5"><i className="h-2.5 w-2.5 rounded-sm" style={{ background: DOWN }} /> lowers risk</span>
        <span className="text-muted">sorted by size of effect</span>
      </div>
      <ul className="space-y-1.5">
        {rows.map((c) => {
          const width = (Math.abs(c.contribution) / max) * 50; // % of the full row, per side
          const up = c.contribution >= 0;
          return (
            <li
              key={c.feature}
              className="grid grid-cols-[minmax(0,11rem)_3.5rem_1fr_3.5rem] items-center gap-3 rounded-lg px-1 py-0.5 text-xs hover:bg-raised"
              title={`${c.label} = ${featureValue(c.value)}: ${up ? "+" : ""}${c.contribution.toFixed(2)} log-odds`}
            >
              <span className="truncate text-ink-2">{c.label}</span>
              <span className="text-right font-mono text-muted tabular">{featureValue(c.value)}</span>
              <span className="relative h-3">
                <span className="absolute inset-y-[-3px] left-1/2 w-px bg-axis" />
                <span
                  className="absolute top-0 h-3"
                  style={{
                    background: up ? UP : DOWN,
                    width: `${width}%`,
                    left: up ? "50%" : `${50 - width}%`,
                    borderRadius: up ? "0 4px 4px 0" : "4px 0 0 4px",
                  }}
                />
              </span>
              <span className="text-right font-mono text-ink-2 tabular">
                {up ? "+" : ""}{c.contribution.toFixed(2)}
              </span>
            </li>
          );
        })}
      </ul>
      {contributions.length > 12 && (
        <button onClick={() => setShowAll((v) => !v)} className="mt-3 text-xs text-accent hover:underline">
          {showAll ? "Show top 12" : `Show all ${contributions.length} features`}
        </button>
      )}
    </div>
  );
}
