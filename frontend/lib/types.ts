// Shapes returned by the FastAPI backend (see backend/phishguard/scanner.py).

export type Verdict = "safe" | "suspicious" | "phishing";
export type Severity = "high" | "medium" | "low" | "info";
export type ScanMode = "fast" | "full";

export interface Reason {
  id: string;
  source: "rule" | "model" | "allowlist";
  weight: number;
  message: string;
  severity: Severity;
  feature: string | null;
}

export interface Contribution {
  feature: string;
  label: string;
  value: number;
  contribution: number; // log-odds; > 0 pushes towards phishing
}

export interface LexicalInfo {
  features: Record<string, number>;
  host: string;
  unicode_host: string;
  registrable_domain: string;
  subdomain: string;
  suffix: string;
  suspicious_words: string[];
  brands_in_host: string[];
  brands_in_path: string[];
  lookalike: { kind: string; brand: string; legit_domain: string; evidence: string } | null;
  mixed_script: boolean;
  platform: string | null;
  shortener: string | null;
}

export interface HostInfo {
  blocked: string | null;
  dns: { resolves: boolean; a: string[]; aaaa_count: number; mx_count: number; ns_count: number;
         min_ttl: number | null; error: string | null } | null;
  tls: { https: boolean; valid: boolean; error: string | null; issuer: string | null; subject: string | null;
         not_before: string | null; not_after: string | null; age_days: number | null; days_left: number | null;
         san_count: number; version: string | null } | null;
  whois: { created: string | null; age_days: number | null; registrar: string | null; source: string | null;
           error: string | null } | null;
}

export interface PageInfo {
  final_url: string;
  status: number | null;
  redirects: string[];
  error: string | null;
  final_is_https: boolean;
  title?: string;
  forms?: { action: string; kind: string; has_password: boolean; method: string }[];
  form_count?: number;
  password_fields?: number;
  external_form_count?: number;
  external_password_form?: boolean;
  mailto_form?: boolean;
  iframe_count?: number;
  meta_refresh_to?: string | null;
  brands_in_title?: string[];
  brands_in_text?: string[];
}

export interface ScanResult {
  url: string;
  normalized_url: string;
  host: string;
  unicode_host: string;
  domain: string;
  final_domain: string | null;
  mode: ScanMode;
  score: number;
  verdict: Verdict;
  model_probability: number;
  known_good: boolean;
  reasons: Reason[];
  contributions: Contribution[];
  features: { lexical: LexicalInfo; host: HostInfo | null; page: PageInfo | null };
  cached: boolean;
  latency_ms: number;
  scanned_at: string;
  scan_id?: number;
}

export interface HistoryRow {
  id: number;
  created_at: string;
  url: string;
  domain: string;
  mode: ScanMode;
  score: number;
  verdict: Verdict;
  client: string;
  cached: number;
  latency_ms: number;
}

export interface Stats {
  total_scans: number;
  by_verdict: Record<Verdict, number>;
  by_client: Record<string, number>;
  flagged_rate: number;
  cache_hit_rate: number;
  latency_ms: Record<ScanMode, { count: number; p50: number | null; p95: number | null }>;
  per_day: { day: string; total: number; safe: number; suspicious: number; phishing: number }[];
  cache: { size: number; hits: number; misses: number; hit_rate: number };
}

export interface TopDomain {
  domain: string;
  scans: number;
  max_score: number;
  avg_score: number;
  last_seen: string;
}

export interface ClassMetrics {
  n: number;
  threshold: number;
  accuracy: number;
  precision: number;
  recall: number;
  f1: number;
  false_positive_rate: number;
  confusion: { tn: number; fp: number; fn: number; tp: number };
  roc_auc?: number;
  pr_auc?: number;
}

export interface ModelMetrics {
  trained_at: string;
  model: string;
  feature_names: string[];
  dataset: { name: string; rows: number; phishing: number; legitimate: number; domains: number;
             train_rows: number; test_rows: number; split: string };
  score_bands: { suspicious_at: number; phishing_at: number };
  cv: { folds: number; f1_mean: number; f1_std: number; roc_auc_mean: number; roc_auc_std: number };
  test: {
    model: ClassMetrics;
    baseline_logreg: ClassMetrics;
    system_suspicious: ClassMetrics;
    system_phishing: ClassMetrics;
    thresholds: ClassMetrics[];
    pr_curve: { threshold: number; precision: number; recall: number }[];
    score_histogram: { legit: number[]; phishing: number[] };
  };
  feature_importance: { feature: string; label: string; importance: number }[];
  external: { phiusiil?: {
    rows: number; phishing: number; model: ClassMetrics; system_phishing: ClassMetrics;
    system_suspicious: ClassMetrics;
    phishing_with_path: { n: number; recall_suspicious: number };
    phishing_bare_domain: { n: number; recall_suspicious: number };
  } };
  leakage_experiment: { description: string; in_distribution: ClassMetrics; on_mendeley: ClassMetrics;
                        top_features: string[] } | null;
}
