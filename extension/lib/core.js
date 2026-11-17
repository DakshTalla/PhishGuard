// Pure helpers shared by the service worker, popup, options and warning pages.
// No chrome.* calls in here, so `node --test` can test every function.

export const DEFAULT_SETTINGS = Object.freeze({
  apiBase: "http://127.0.0.1:8000",
  threshold: 70, // warn at the backend's "phishing" band by default
  enabled: true,
  allowlist: [],
});

// Same bands as backend/phishguard/scoring.py.
export const SUSPICIOUS_AT = 40;
export const PHISHING_AT = 70;

// A shortened link says nothing about where it goes, so the extension waits
// for the redirect to finish and checks the destination instead.
const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
  "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "t.ly", "s.id", "v.gd", "lnkd.in",
]);

export function bandFor(score) {
  if (score >= PHISHING_AT) return "phishing";
  if (score >= SUSPICIOUS_AT) return "suspicious";
  return "safe";
}

export function hostOf(url) {
  try {
    return new URL(url).hostname.toLowerCase().replace(/\.$/, "");
  } catch {
    return "";
  }
}

/** Turn whatever the user typed ("https://Example.com/x", "*.example.com") into "example.com". */
export function normalizeAllowEntry(input) {
  let text = String(input || "").trim().toLowerCase();
  if (!text) return "";
  text = text.replace(/^\*\./, "");
  const host = text.includes("://") ? hostOf(text) : hostOf(`http://${text}`);
  return /^[a-z0-9.-]+$/.test(host) && host.includes(".") ? host : "";
}

/** An entry covers itself and every subdomain: "example.com" allows "a.example.com". */
export function isAllowlisted(host, allowlist) {
  return (allowlist || []).some((entry) => host === entry || host.endsWith(`.${entry}`));
}

export function isShortener(host) {
  return SHORTENERS.has(host);
}

function isPrivateHost(host) {
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) return true;
  if (host.startsWith("[")) return true; // IPv6 literals: almost always local in practice
  const m = host.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  return a === 10 || a === 127 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || (a === 169 && b === 254);
}

/**
 * Should this navigation be sent to the API at all?
 * Skips non-web URLs, the API itself, local/intranet hosts and allowlisted sites.
 */
export function shouldScan(url, settings) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;
  const host = parsed.hostname.toLowerCase();
  if (isPrivateHost(host)) return false;
  if (hostOf(settings.apiBase) === host) return false;
  return !isAllowlisted(host, settings.allowlist);
}

/** Pick the reasons worth showing in a small popup: risky ones first, then a little context. */
export function topReasons(reasons, limit = 4) {
  const risky = (reasons || []).filter((r) => r.severity !== "info");
  const info = (reasons || []).filter((r) => r.severity === "info");
  return [...risky, ...info].slice(0, limit);
}
