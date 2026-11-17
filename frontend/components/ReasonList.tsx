import type { Reason, Severity } from "@/lib/types";

const DOT: Record<Severity, string> = {
  high: "var(--color-critical)",
  medium: "var(--color-warning)",
  low: "var(--color-muted)",
  info: "var(--color-good)",
};
const SEVERITY_LABEL: Record<Severity, string> = { high: "High", medium: "Medium", low: "Low", info: "Context" };
const SOURCE_LABEL = { rule: "Rule", model: "ML model", allowlist: "Known site" } as const;

function Item({ reason }: { reason: Reason }) {
  return (
    <li className="flex gap-3 rounded-xl border border-line bg-raised/60 px-3.5 py-2.5">
      <span className="mt-1.5 h-2 w-2 flex-none rounded-full" style={{ background: DOT[reason.severity] }} aria-hidden="true" />
      <div className="min-w-0">
        {/* React escapes text, so attacker-controlled hosts in messages cannot inject HTML. */}
        <p className="text-sm text-ink">{reason.message}</p>
        <p className="mt-0.5 text-[11px] uppercase tracking-wide text-muted">
          {SEVERITY_LABEL[reason.severity]} · {SOURCE_LABEL[reason.source]}
        </p>
      </div>
    </li>
  );
}

export default function ReasonList({ reasons }: { reasons: Reason[] }) {
  const risky = reasons.filter((r) => r.severity !== "info");
  const context = reasons.filter((r) => r.severity === "info");
  return (
    <div className="space-y-5">
      <div>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">Why this score</h3>
        {risky.length ? (
          <ul className="space-y-2">{risky.map((r) => <Item key={r.id} reason={r} />)}</ul>
        ) : (
          <p className="text-sm text-ink-2">No risky signals found.</p>
        )}
      </div>
      {context.length > 0 && (
        <div>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">Context</h3>
          <ul className="space-y-2">{context.map((r) => <Item key={r.id} reason={r} />)}</ul>
        </div>
      )}
    </div>
  );
}
