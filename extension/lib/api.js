// Talking to the PhishGuard API and to extension storage.
import { DEFAULT_SETTINGS } from "./core.js";

export async function getSettings() {
  // storage.sync follows the user across their Chrome profiles; it is small,
  // which is fine for a handful of settings and an allowlist.
  const stored = await chrome.storage.sync.get(DEFAULT_SETTINGS);
  return { ...DEFAULT_SETTINGS, ...stored };
}

export async function saveSettings(patch) {
  await chrome.storage.sync.set(patch);
}

/**
 * POST /api/scan with a timeout. Returns the result, or null when the API is
 * unreachable. The caller then FAILS OPEN (lets the page load): an outage of
 * the local backend should not make the whole web unusable.
 */
export async function scan(apiBase, url, mode = "fast", timeoutMs = 3000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), mode === "full" ? 15000 : timeoutMs);
  try {
    const res = await fetch(`${apiBase.replace(/\/$/, "")}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-PhishGuard-Client": "extension" },
      body: JSON.stringify({ url, mode }),
      signal: controller.signal,
    });
    if (!res.ok) return { error: `API answered ${res.status}` };
    return await res.json();
  } catch (err) {
    return { error: err.name === "AbortError" ? "API timed out" : "API unreachable" };
  } finally {
    clearTimeout(timer);
  }
}
