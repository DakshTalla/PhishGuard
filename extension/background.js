// Service worker: checks every top-level navigation and redirects risky ones
// to a warning page.
//
// WHY webNavigation + tabs.update instead of blocking the request: Manifest V3
// removed blocking webRequest for normal extensions. So we start the (fast,
// ~10 ms) scan as soon as Chrome *starts* a navigation, and if the verdict is
// risky we replace the tab's URL with our warning page. The scan usually wins
// the race against DNS + TLS + first byte; on a slow API the page may flash
// briefly before the warning appears. Repeat visits are answered from the
// in-memory cache, so the redirect happens before any network round-trip.
import { bandFor, hostOf, isShortener, shouldScan } from "./lib/core.js";
import { getSettings, saveSettings, scan } from "./lib/api.js";

const CACHE_MS = 10 * 60 * 1000;
const cache = new Map(); // url -> { result, at }  (lost when the worker sleeps; the API caches too)
const inflight = new Map(); // url -> Promise, so onBeforeNavigate + onCommitted share one request

const BADGE_COLORS = { safe: "#16a34a", suspicious: "#d97706", phishing: "#dc2626" };

async function cachedScan(apiBase, url) {
  const hit = cache.get(url);
  if (hit && Date.now() - hit.at < CACHE_MS) return hit.result;
  if (inflight.has(url)) return inflight.get(url);
  const pending = scan(apiBase, url, "fast").then((result) => {
    inflight.delete(url);
    if (!result.error) {
      cache.set(url, { result, at: Date.now() });
      if (cache.size > 500) cache.delete(cache.keys().next().value); // oldest first
    }
    return result;
  });
  inflight.set(url, pending);
  return pending;
}

async function bypassed(host) {
  // Hosts the user chose to visit anyway, until the browser closes.
  const { bypass = [] } = await chrome.storage.session.get("bypass");
  return bypass.includes(host);
}

async function showBadge(tabId, result) {
  if (!result || result.error) {
    await chrome.action.setBadgeText({ tabId, text: "?" });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: "#64748b" });
    return;
  }
  await chrome.action.setBadgeText({ tabId, text: String(result.score) });
  await chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLORS[bandFor(result.score)] });
}

async function checkNavigation(tabId, url, phase) {
  const settings = await getSettings();
  if (!settings.enabled || !shouldScan(url, settings)) {
    await chrome.action.setBadgeText({ tabId, text: "" });
    return;
  }
  const host = hostOf(url);
  // For a shortener, wait for onCommitted: by then Chrome has followed the
  // redirect and `url` is the real destination.
  if (phase === "before" && isShortener(host)) return;
  if (await bypassed(host)) return;

  const result = await cachedScan(settings.apiBase, url);
  await chrome.storage.session.set({ [`tab:${tabId}`]: { url, result } });
  await showBadge(tabId, result);

  if (!result.error && result.score >= settings.threshold) {
    await chrome.storage.session.set({ [`warn:${tabId}`]: { url, result } });
    const warning = chrome.runtime.getURL(`warning.html?tab=${tabId}&url=${encodeURIComponent(url)}`);
    await chrome.tabs.update(tabId, { url: warning });
  }
}

chrome.webNavigation.onBeforeNavigate.addListener((d) => {
  if (d.frameId === 0) checkNavigation(d.tabId, d.url, "before");
});

chrome.webNavigation.onCommitted.addListener((d) => {
  // Catches server-side redirects; usually a cache hit for normal pages.
  if (d.frameId === 0) checkNavigation(d.tabId, d.url, "committed");
});

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.remove([`tab:${tabId}`, `warn:${tabId}`]);
});

// Messages from the warning page and the popup.
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    if (msg.type === "proceed") {
      const { bypass = [] } = await chrome.storage.session.get("bypass");
      await chrome.storage.session.set({ bypass: [...new Set([...bypass, hostOf(msg.url)])] });
      await chrome.tabs.update(msg.tabId, { url: msg.url });
    } else if (msg.type === "trust") {
      const settings = await getSettings();
      const allowlist = [...new Set([...settings.allowlist, msg.domain])].sort();
      await saveSettings({ allowlist });
      if (msg.url) await chrome.tabs.update(msg.tabId, { url: msg.url });
    } else if (msg.type === "leave") {
      await chrome.tabs.update(msg.tabId, { url: "chrome://newtab/" });
    }
    sendResponse({ ok: true });
  })();
  return true; // keep the channel open for the async reply
});
