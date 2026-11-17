"use client";

import {
  Bar, BarChart, CartesianGrid, Legend, Line, LineChart, ReferenceDot, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";

import { pct } from "@/lib/format";
import type { ClassMetrics, ModelMetrics as Metrics } from "@/lib/types";
import ChartCard, { AXIS, TipBox, legendText } from "./ChartCard";
import StatTile from "./StatTile";

const BLUE = "#3987e5";   // categorical slot 1
const ORANGE = "#d95926"; // categorical slot 2

function ConfusionMatrix({ m }: { m: ClassMetrics }) {
  const { tn, fp, fn, tp } = m.confusion;
  const max = Math.max(tn, fp, fn, tp);
  const cells = [
    { label: "Legit, not flagged", value: tn, good: true },
    { label: "Legit, flagged (false positive)", value: fp, good: false },
    { label: "Phishing, missed (false negative)", value: fn, good: false },
    { label: "Phishing, flagged", value: tp, good: true },
  ];
  return (
    <section className="rounded-2xl border border-line bg-surface p-5">
      <h2 className="text-sm font-semibold">Confusion matrix</h2>
      <p className="mt-0.5 text-xs text-muted">Model + rules on {m.n.toLocaleString()} test URLs from unseen domains, flagged at score ≥ {Math.round(m.threshold * 100)}</p>
      <div className="mt-4 grid grid-cols-[auto_1fr_1fr] gap-1.5 text-xs">
        <span />
        <span className="pb-1 text-center text-muted">Not flagged</span>
        <span className="pb-1 text-center text-muted">Flagged</span>
        {["Actually legit", "Actually phishing"].map((rowLabel, r) => (
          <div key={rowLabel} className="contents">
            <span className="flex items-center pr-2 text-muted">{rowLabel}</span>
            {cells.slice(r * 2, r * 2 + 2).map((c) => (
              <div
                key={c.label}
                title={c.label}
                className="rounded-lg px-3 py-4 text-center"
                // Sequential blue: darker = more URLs. Text stays in ink colours.
                style={{ background: `rgba(57,135,229,${0.12 + 0.6 * (c.value / max)})` }}
              >
                <div className="text-xl font-semibold tabular">{c.value.toLocaleString()}</div>
                <div className="mt-0.5 text-[11px] text-ink-2">{c.good ? "correct" : c.label.split("(")[1]?.replace(")", "")}</div>
              </div>
            ))}
          </div>
        ))}
      </div>
    </section>
  );
}

function ComparisonTable({ metrics }: { metrics: Metrics }) {
  const rows: [string, ClassMetrics][] = [
    ["XGBoost (served)", metrics.test.model],
    ["Logistic regression baseline", metrics.test.baseline_logreg],
    [`Model + rules, score ≥ ${metrics.score_bands.suspicious_at}`, metrics.test.system_suspicious],
    [`Model + rules, score ≥ ${metrics.score_bands.phishing_at}`, metrics.test.system_phishing],
  ];
  return (
    <section className="rounded-2xl border border-line bg-surface p-5">
      <h2 className="text-sm font-semibold">Model comparison on the test set</h2>
      <p className="mt-0.5 text-xs text-muted">Models at probability 0.5; the system at the two score bands the app uses</p>
      <div className="mt-3 overflow-x-auto">
        <table className="w-full min-w-[560px] text-left text-xs tabular">
          <thead className="text-muted">
            <tr className="border-b border-line">
              {["", "Accuracy", "Precision", "Recall", "F1", "False-pos. rate", "ROC-AUC"].map((h) => (
                <th key={h} className="py-2 pr-3 font-medium">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map(([name, m]) => (
              <tr key={name} className="border-b border-line/50">
                <td className="py-2 pr-3 text-ink">{name}</td>
                <td className="py-2 pr-3 text-ink-2">{pct(m.accuracy)}</td>
                <td className="py-2 pr-3 text-ink-2">{pct(m.precision)}</td>
                <td className="py-2 pr-3 text-ink-2">{pct(m.recall)}</td>
                <td className="py-2 pr-3 text-ink-2">{m.f1.toFixed(3)}</td>
                <td className="py-2 pr-3 text-ink-2">{pct(m.false_positive_rate)}</td>
                <td className="py-2 pr-3 text-ink-2">{m.roc_auc?.toFixed(3) ?? "–"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export default function ModelMetrics({ metrics }: { metrics: Metrics }) {
  const sys = metrics.test.system_phishing;
  const ext = metrics.external.phiusiil;
  const leak = metrics.leakage_experiment;

  const pr = [...metrics.test.pr_curve].sort((a, b) => a.recall - b.recall)
    .map((p) => ({ recall: p.recall, precision: p.precision, threshold: p.threshold }));
  const hist = metrics.test.score_histogram.legit.map((legit, i) => ({
    bucket: `${i * 10}–${i * 10 + 9}`, legit, phishing: metrics.test.score_histogram.phishing[i],
  }));
  const importance = metrics.feature_importance.slice(0, 10);
  const maxImp = importance[0]?.importance ?? 1;

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-6">
        <StatTile label="ROC-AUC, unseen domains" value={metrics.test.model.roc_auc?.toFixed(3) ?? "–"} note={`CV ${metrics.cv.roc_auc_mean.toFixed(3)} ± ${metrics.cv.roc_auc_std.toFixed(3)}`} />
        <StatTile label="Precision at score 70" value={pct(sys.precision)} note="of flagged URLs are phishing" />
        <StatTile label="Recall at score 70" value={pct(sys.recall)} note="of phishing URLs flagged" />
        <StatTile label="False-positive rate" value={pct(sys.false_positive_rate)} note="legit URLs flagged at 70" />
        <StatTile label="External ROC-AUC" value={ext?.model.roc_auc?.toFixed(3) ?? "–"} note={ext ? `PhiUSIIL, ${(ext.rows / 1000).toFixed(0)}K URLs` : "not evaluated"} />
        <StatTile label="External precision" value={ext ? pct(ext.system_phishing.precision) : "–"} note="at score 70" />
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        <ChartCard
          title="Precision-recall curve"
          subtitle="Model alone on the test set; the dot is the default 0.5 threshold"
          columns={["Threshold", "Recall", "Precision"]}
          rows={pr.map((p) => [p.threshold.toFixed(3), pct(p.recall), pct(p.precision)])}
          chart={
            <ResponsiveContainer width="100%" height={240}>
              <LineChart data={pr} margin={{ top: 8, right: 12, left: -12, bottom: 0 }}>
                <CartesianGrid stroke="#2c2c2a" />
                <XAxis dataKey="recall" type="number" domain={[0, 1]} tickFormatter={(v) => `${Math.round(v * 100)}%`} {...AXIS} />
                <YAxis type="number" domain={[0.4, 1]} tickFormatter={(v) => `${Math.round(v * 100)}%`} {...AXIS} />
                <Tooltip
                  content={({ active, payload }) => active && payload?.length ? (
                    <TipBox active label={`threshold ${Number(payload[0].payload.threshold).toFixed(2)}`}
                      payload={[{ name: "Recall", value: pct(payload[0].payload.recall), color: BLUE },
                                { name: "Precision", value: pct(payload[0].payload.precision), color: BLUE }]} />
                  ) : null}
                />
                <Line dataKey="precision" stroke={BLUE} strokeWidth={2} dot={false} isAnimationActive={false} />
                <ReferenceDot x={metrics.test.model.recall} y={metrics.test.model.precision} r={5} fill={BLUE} stroke="#1a1a19" strokeWidth={2} />
              </LineChart>
            </ResponsiveContainer>
          }
        />
        <ChartCard
          title="Score separation"
          subtitle="How many test URLs land in each score range (model + rules)"
          columns={["Score", "Legitimate", "Phishing"]}
          rows={hist.map((h) => [h.bucket, h.legit, h.phishing])}
          chart={
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={hist} margin={{ top: 8, right: 4, left: -12, bottom: 0 }} barGap={2}>
                <CartesianGrid vertical={false} stroke="#2c2c2a" />
                <XAxis dataKey="bucket" {...AXIS} interval={1} />
                <YAxis {...AXIS} axisLine={false} />
                <Tooltip cursor={{ fill: "rgba(255,255,255,0.04)" }} content={(p) => <TipBox {...p} labelPrefix="Score " />} />
                <Legend iconType="circle" iconSize={8} itemSorter={(item) => (item.dataKey === "legit" ? 0 : 1)} wrapperStyle={{ fontSize: 12 }} formatter={legendText} />
                <Bar dataKey="legit" name="Legitimate" fill={BLUE} radius={[4, 4, 0, 0]} maxBarSize={14} isAnimationActive={false} />
                <Bar dataKey="phishing" name="Phishing" fill={ORANGE} radius={[4, 4, 0, 0]} maxBarSize={14} isAnimationActive={false} />
              </BarChart>
            </ResponsiveContainer>
          }
        />
      </div>

      <div className="grid gap-5 lg:grid-cols-[1fr_1.2fr]">
        <ConfusionMatrix m={sys} />
        <section className="rounded-2xl border border-line bg-surface p-5">
          <h2 className="text-sm font-semibold">Threshold trade-off</h2>
          <p className="mt-0.5 text-xs text-muted">Lower thresholds catch more phishing but warn on more safe sites</p>
          <div className="mt-3 overflow-x-auto">
            <table className="w-full text-left text-xs tabular">
              <thead className="text-muted">
                <tr className="border-b border-line">
                  {["Flag at score ≥", "Precision", "Recall", "False-pos. rate"].map((h) => <th key={h} className="py-1.5 pr-3 font-medium">{h}</th>)}
                </tr>
              </thead>
              <tbody>
                {metrics.test.thresholds.map((t) => {
                  const score = Math.round(t.threshold * 100);
                  const band = score === metrics.score_bands.phishing_at || score === metrics.score_bands.suspicious_at;
                  return (
                    <tr key={score} className={`border-b border-line/50 ${band ? "bg-accent/10" : ""}`}>
                      <td className="py-1.5 pr-3 text-ink">{score}{band ? (score === 70 ? "  (phishing band)" : "  (suspicious band)") : ""}</td>
                      <td className="py-1.5 pr-3 text-ink-2">{pct(t.precision)}</td>
                      <td className="py-1.5 pr-3 text-ink-2">{pct(t.recall)}</td>
                      <td className="py-1.5 pr-3 text-ink-2">{pct(t.false_positive_rate)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        <section className="rounded-2xl border border-line bg-surface p-5">
          <h2 className="text-sm font-semibold">What the model relies on</h2>
          <p className="mt-0.5 text-xs text-muted">Mean absolute contribution (log-odds) per feature on the test set</p>
          <ul className="mt-4 space-y-2">
            {importance.map((f) => (
              <li key={f.feature} className="grid grid-cols-[10rem_1fr] items-center gap-3 text-xs" title={`${f.label}: ${f.importance}`}>
                <span className="truncate text-ink-2">{f.label}</span>
                <span className="flex items-center gap-2">
                  <span className="h-2.5 rounded-r" style={{ width: `${(f.importance / maxImp) * 80}%`, background: BLUE }} />
                  <span className="text-ink-2 tabular">{f.importance.toFixed(2)}</span>
                </span>
              </li>
            ))}
          </ul>
        </section>
        <section className="rounded-2xl border border-line bg-surface p-5">
          <h2 className="text-sm font-semibold">Training data and the leakage check</h2>
          <dl className="mt-3 space-y-2 text-xs">
            <div className="flex justify-between gap-4"><dt className="text-muted">Dataset</dt><dd className="text-right text-ink-2">{metrics.dataset.name}</dd></div>
            <div className="flex justify-between gap-4"><dt className="text-muted">URLs / domains</dt><dd className="text-ink-2 tabular">{metrics.dataset.rows.toLocaleString()} / {metrics.dataset.domains.toLocaleString()}</dd></div>
            <div className="flex justify-between gap-4"><dt className="text-muted">Split</dt><dd className="text-right text-ink-2">{metrics.dataset.split}</dd></div>
            <div className="flex justify-between gap-4"><dt className="text-muted">Trained</dt><dd className="text-ink-2">{metrics.trained_at.slice(0, 10)}</dd></div>
          </dl>
          {leak && (
            <div className="mt-4 rounded-xl border border-warning/30 bg-warning/5 p-3 text-xs leading-relaxed text-ink-2">
              <p className="font-semibold text-ink">Why not train on the 235K-URL PhiUSIIL set?</p>
              <p className="mt-1">
                Every legitimate URL in it is a bare <span className="font-mono">https://www.</span> homepage. A model trained on it
                scores <b className="text-ink">{pct(leak.in_distribution.accuracy)}</b> on its own test split but
                only <b className="text-ink">{pct(leak.on_mendeley.accuracy)}</b> on real-world URLs, flagging{" "}
                <b className="text-ink">{pct(leak.on_mendeley.false_positive_rate, 0)}</b> of legitimate ones. Its top
                feature was “{leak.top_features[0]}”: it learned the URL shape, not phishing.
              </p>
            </div>
          )}
        </section>
      </div>

      <ComparisonTable metrics={metrics} />
    </div>
  );
}
