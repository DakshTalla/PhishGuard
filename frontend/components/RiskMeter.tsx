"use client";

import { useEffect, useRef, useState } from "react";

import { BAND_META, PHISHING_AT, SUSPICIOUS_AT, bandFor, easeOut } from "@/lib/format";

// Semicircle gauge. The arc's fill colour carries severity; the track is a
// quiet grey; tick marks show where the "suspicious" and "phishing" bands begin.
const CX = 120;
const CY = 118;
const R = 96;
const ARC = `M ${CX - R} ${CY} A ${R} ${R} 0 0 1 ${CX + R} ${CY}`;

function point(score: number, radius: number) {
  const angle = Math.PI * (1 - score / 100); // 180deg (left) -> 0deg (right)
  return { x: CX + radius * Math.cos(angle), y: CY - radius * Math.sin(angle) };
}

export default function RiskMeter({ score }: { score: number }) {
  const [shown, setShown] = useState(0);
  const from = useRef(0);

  useEffect(() => {
    // Animate from the previous value to the new one with requestAnimationFrame.
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const start = performance.now();
    const begin = from.current;
    const duration = reduce ? 0 : 900;
    let frame = 0;
    const tick = (now: number) => {
      const t = duration ? (now - start) / duration : 1;
      const value = begin + (score - begin) * easeOut(t);
      setShown(value);
      if (t < 1) frame = requestAnimationFrame(tick);
      else from.current = score;
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [score]);

  const band = bandFor(Math.round(shown));
  const meta = BAND_META[band];
  const needle = point(shown, R - 26);

  return (
    <div className="flex flex-col items-center" role="img" aria-label={`Risk score ${score} of 100: ${BAND_META[bandFor(score)].label}`}>
      <svg viewBox="0 0 240 140" className="w-full max-w-[320px]">
        <path d={ARC} fill="none" stroke="var(--color-line)" strokeWidth="16" strokeLinecap="round" />
        <path
          d={ARC}
          fill="none"
          stroke={meta.color}
          strokeWidth="16"
          strokeLinecap="round"
          pathLength={100}
          strokeDasharray="100 100"
          strokeDashoffset={100 - Math.max(shown, 0.5)}
        />
        {[SUSPICIOUS_AT, PHISHING_AT].map((t) => {
          const a = point(t, R + 12);
          const b = point(t, R + 20);
          return <line key={t} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="var(--color-muted)" strokeWidth="1.5" />;
        })}
        <line x1={CX} y1={CY} x2={needle.x} y2={needle.y} stroke="var(--color-ink)" strokeWidth="3" strokeLinecap="round" />
        <circle cx={CX} cy={CY} r="6" fill="var(--color-ink)" stroke="var(--color-surface)" strokeWidth="2" />
      </svg>
      <div className="-mt-3 text-5xl font-semibold tabular">{Math.round(shown)}</div>
      <div className="mt-1 flex items-center gap-2 text-sm font-medium text-ink-2">
        <span
          className="grid h-5 w-5 place-items-center rounded-full text-[11px] font-bold text-page"
          style={{ background: meta.color }}
          aria-hidden="true"
        >
          {meta.icon}
        </span>
        {meta.label}
      </div>
    </div>
  );
}
