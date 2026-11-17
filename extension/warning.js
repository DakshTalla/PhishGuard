// Interstitial shown instead of a risky page.
import { DEMO_RESULT, isDemo } from "./lib/demo.js";
import { renderReasons, renderRing, setVerdictPill } from "./lib/ui.js";

const params = new URLSearchParams(location.search);
const tabId = Number(params.get("tab"));
const blockedUrl = params.get("url") || DEMO_RESULT.url;

async function load() {
  if (isDemo()) return DEMO_RESULT;
  const key = `warn:${tabId}`;
  const stored = (await chrome.storage.session.get(key))[key];
  return stored && stored.url === blockedUrl ? stored.result : null;
}

function send(message) {
  if (isDemo()) return;
  chrome.runtime.sendMessage({ ...message, tabId });
}

const result = await load();
document.getElementById("url").textContent = blockedUrl; // textContent: the URL is attacker-controlled
if (result) {
  renderRing(document.getElementById("ring"), result.score);
  setVerdictPill(document.getElementById("pill"), result.score);
  renderReasons(document.getElementById("reasons"), result.reasons, 6);
  document.getElementById("domain").textContent = result.domain;
} else {
  document.getElementById("trust").hidden = true;
}

document.getElementById("leave").addEventListener("click", () => send({ type: "leave" }));
document.getElementById("proceed").addEventListener("click", () => send({ type: "proceed", url: blockedUrl }));
document.getElementById("trust").addEventListener("click", () =>
  send({ type: "trust", domain: result.domain, url: blockedUrl }));
