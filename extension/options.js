// Settings page: threshold, API address, on/off and the allowlist.
import { getSettings, saveSettings } from "./lib/api.js";
import { normalizeAllowEntry } from "./lib/core.js";

const $ = (id) => document.getElementById(id);
let settings = await getSettings();

function renderAllowlist() {
  const ul = $("allowlist");
  ul.replaceChildren();
  if (!settings.allowlist.length) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = "No trusted sites yet.";
    ul.append(li);
  }
  for (const entry of settings.allowlist) {
    const li = document.createElement("li");
    const name = document.createElement("span");
    name.className = "mono";
    name.textContent = entry;
    const remove = document.createElement("button");
    remove.className = "btn danger";
    remove.textContent = "Remove";
    remove.onclick = async () => {
      settings.allowlist = settings.allowlist.filter((e) => e !== entry);
      await saveSettings({ allowlist: settings.allowlist });
      renderAllowlist();
    };
    li.append(name, remove);
    ul.append(li);
  }
}

$("enabled").checked = settings.enabled;
$("threshold").value = settings.threshold;
$("thresholdValue").textContent = settings.threshold;
$("apiBase").value = settings.apiBase;
$("threshold").oninput = () => ($("thresholdValue").textContent = $("threshold").value);

$("save").onclick = async () => {
  let apiBase = $("apiBase").value.trim() || "http://127.0.0.1:8000";
  try {
    apiBase = new URL(apiBase).origin;
  } catch {
    $("apiBase").setCustomValidity("Enter a URL such as http://127.0.0.1:8000");
    $("apiBase").reportValidity();
    return;
  }
  settings = { ...settings, enabled: $("enabled").checked, threshold: Number($("threshold").value), apiBase };
  await saveSettings({ enabled: settings.enabled, threshold: settings.threshold, apiBase });
  $("saved").hidden = false;
  setTimeout(() => ($("saved").hidden = true), 1500);
};

$("add").onclick = async () => {
  const entry = normalizeAllowEntry($("newEntry").value);
  if (!entry) {
    $("newEntry").setCustomValidity("Enter a domain such as example.com");
    $("newEntry").reportValidity();
    return;
  }
  $("newEntry").setCustomValidity("");
  settings.allowlist = [...new Set([...settings.allowlist, entry])].sort();
  await saveSettings({ allowlist: settings.allowlist });
  $("newEntry").value = "";
  renderAllowlist();
};
$("newEntry").addEventListener("keydown", (e) => e.key === "Enter" && $("add").click());

renderAllowlist();
