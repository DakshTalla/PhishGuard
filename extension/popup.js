// Toolbar popup: score and reasons for the current tab, deep scan, allowlist toggle.
import { getSettings, saveSettings, scan } from "./lib/api.js";
import { hostOf, isAllowlisted, shouldScan } from "./lib/core.js";
import { DEMO_RESULT, isDemo } from "./lib/demo.js";
import { renderReasons, renderRing, setVerdictPill } from "./lib/ui.js";

const $ = (id) => document.getElementById(id);

function showState(text, isError = false) {
  $("state").hidden = false;
  $("state").textContent = text;
  $("state").classList.toggle("error", isError);
  $("result").hidden = true;
}

function showResult(result) {
  $("state").hidden = true;
  $("result").hidden = false;
  renderRing($("ring"), result.score);
  setVerdictPill($("pill"), result.score);
  $("host").textContent = result.host || hostOf(result.normalized_url);
  $("meta").textContent = `${result.mode === "full" ? "Deep scan" : "Quick scan"}${result.cached ? " (cached)" : ""}`
    + (result.latency_ms != null ? ` - ${Math.round(result.latency_ms)} ms` : "");
  renderReasons($("reasons"), result.reasons);
}

async function main() {
  if (isDemo()) return showResult(DEMO_RESULT);

  const settings = await getSettings();
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tab?.url || "";
  const host = hostOf(url);

  if (!/^https?:/.test(url)) return showState("Nothing to scan on this page.");
  if (isAllowlisted(host, settings.allowlist)) {
    showState(`${host} is on your allowlist, so it is not checked.`);
    const undo = document.createElement("button");
    undo.className = "btn";
    undo.style.marginTop = "10px";
    undo.textContent = "Remove from allowlist";
    undo.onclick = async () => {
      await saveSettings({ allowlist: settings.allowlist.filter((e) => !(host === e || host.endsWith(`.${e}`))) });
      location.reload();
    };
    $("state").append(document.createElement("br"), undo);
    return;
  }
  if (!shouldScan(url, settings)) return showState("Local and intranet pages are not checked.");

  // Reuse the service worker's verdict for this tab when it matches.
  const key = `tab:${tab.id}`;
  const stored = (await chrome.storage.session.get(key))[key];
  let result = stored?.url === url && !stored.result.error ? stored.result : await scan(settings.apiBase, url);
  if (result.error) {
    return showState(`${result.error}. Start the backend with start.ps1, or check the API address in Settings.`, true);
  }
  showResult(result);

  $("deep").onclick = async () => {
    $("deep").disabled = true;
    $("deep").textContent = "Scanning...";
    const deep = await scan(settings.apiBase, url, "full");
    $("deep").disabled = false;
    $("deep").textContent = "Deep scan";
    if (deep.error) return showState(deep.error, true);
    result = deep;
    showResult(deep);
  };
  $("trust").onclick = async () => {
    const allowlist = [...new Set([...settings.allowlist, result.domain])].sort();
    await saveSettings({ allowlist });
    await chrome.action.setBadgeText({ tabId: tab.id, text: "" });
    location.reload();
  };
}

main();
