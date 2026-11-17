// Pure formatting helpers (unit-tested in format.test.ts, no React here).

export type Band = "safe" | "suspicious" | "phishing";

// Same thresholds as backend/phishguard/scoring.py and the extension.
export const SUSPICIOUS_AT = 40;
export const PHISHING_AT = 70;

export function bandFor(score: number): Band {
  if (score >= PHISHING_AT) return "phishing";
  if (score >= SUSPICIOUS_AT) return "suspicious";
  return "safe";
}

// Status colours carry *state* and always travel with a text label and icon,
// so meaning never depends on colour alone.
export const BAND_META: Record<Band, { label: string; color: string; icon: string }> = {
  safe: { label: "Looks safe", color: "var(--color-good)", icon: "✓" },
  suspicious: { label: "Suspicious", color: "var(--color-warning)", icon: "!" },
  phishing: { label: "Likely phishing", color: "var(--color-critical)", icon: "✕" },
};

export function pct(value: number | null | undefined, digits = 1): string {
  if (value == null || Number.isNaN(value)) return "–";
  return `${(value * 100).toFixed(digits)}%`;
}

export function ms(value: number | null | undefined): string {
  if (value == null) return "–";
  if (value < 0.01) return "<0.01 ms"; // cache hits
  if (value < 1) return `${value.toFixed(2)} ms`;
  if (value < 1000) return `${Math.round(value)} ms`;
  return `${(value / 1000).toFixed(1)} s`;
}

/** 1,284 / 12.9K / 3.4M, as the stat-tile contract asks. */
export function compact(value: number): string {
  if (Math.abs(value) < 10_000) return value.toLocaleString("en-US");
  return new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 }).format(value);
}

export function timeAgo(iso: string, now: Date = new Date()): string {
  const seconds = Math.max(0, Math.round((now.getTime() - new Date(iso).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86_400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86_400)}d ago`;
}

/** Feature values: integers as-is, ratios and entropies with 2 decimals. */
export function featureValue(value: number): string {
  return Number.isInteger(value) ? String(value) : value.toFixed(2);
}

/** Days -> "3 days", "2 years". */
export function age(days: number | null | undefined): string {
  if (days == null) return "unknown";
  if (days < 60) return `${days} day${days === 1 ? "" : "s"}`;
  if (days < 730) return `${Math.round(days / 30)} months`;
  return `${Math.floor(days / 365)} years`;
}

/** Ease-out cubic, used by the risk meter animation. */
export function easeOut(t: number): number {
  const c = Math.min(1, Math.max(0, t));
  return 1 - (1 - c) ** 3;
}
