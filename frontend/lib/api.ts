// Browser-side calls to the FastAPI backend. The backend's CORS settings
// allow this origin (http://localhost:3100).
import type { HistoryRow, ModelMetrics, ScanMode, ScanResult, Stats, TopDomain } from "./types";

export const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? "http://127.0.0.1:8000";
const TOKEN_KEY = "phishguard-admin-token";

export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, init);
  } catch {
    throw new ApiError(`Cannot reach the API at ${API_BASE}. Is the backend running?`, 0);
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    const detail = typeof body.detail === "string" ? body.detail : res.statusText;
    const retry = res.headers.get("Retry-After");
    throw new ApiError(res.status === 429 && retry ? `${detail}; try again in ${retry}s` : detail, res.status);
  }
  return res.json() as Promise<T>;
}

export function scanUrl(url: string, mode: ScanMode): Promise<ScanResult> {
  return request<ScanResult>("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-PhishGuard-Client": "web" },
    body: JSON.stringify({ url, mode }),
  });
}

export async function health(): Promise<boolean> {
  try {
    await request("/api/health");
    return true;
  } catch {
    return false;
  }
}

// --- admin -------------------------------------------------------------------
// The token (only needed when the backend sets PHISHGUARD_ADMIN_TOKEN) lives in
// sessionStorage: it is forgotten when the tab closes and never put in a URL.

export function getAdminToken(): string {
  if (typeof window === "undefined") return "";
  try {
    return sessionStorage.getItem(TOKEN_KEY) ?? "";
  } catch {
    return "";
  }
}

export function setAdminToken(token: string): void {
  try {
    sessionStorage.setItem(TOKEN_KEY, token);
  } catch {
    /* storage blocked: the token simply is not remembered */
  }
}

function admin<T>(path: string): Promise<T> {
  return request<T>(path, { headers: { "X-Admin-Token": getAdminToken() } });
}

export const adminApi = {
  stats: () => admin<Stats>("/api/admin/stats"),
  history: (params: { verdict?: string; q?: string; limit?: number }) => {
    const qs = new URLSearchParams();
    if (params.verdict) qs.set("verdict", params.verdict);
    if (params.q) qs.set("q", params.q);
    qs.set("limit", String(params.limit ?? 50));
    return admin<HistoryRow[]>(`/api/admin/history?${qs}`);
  },
  scan: (id: number) => admin<ScanResult>(`/api/admin/scans/${id}`),
  topDomains: () => admin<TopDomain[]>("/api/admin/top-domains?limit=8"),
  metrics: () => admin<ModelMetrics>("/api/admin/metrics"),
};
