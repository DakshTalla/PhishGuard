// Small DOM helpers shared by the popup and the warning page.
import { bandFor, topReasons } from "./core.js";

const COLORS = { safe: "#22c55e", suspicious: "#f59e0b", phishing: "#ef4444" };

/** Fill an element with a circular score gauge. */
export function renderRing(el, score) {
  const r = 36;
  const circumference = 2 * Math.PI * r;
  const band = bandFor(score);
  el.innerHTML = `
    <svg width="84" height="84" viewBox="0 0 84 84" aria-hidden="true">
      <circle class="track" cx="42" cy="42" r="${r}" fill="none" stroke-width="8"></circle>
      <circle class="value" cx="42" cy="42" r="${r}" fill="none" stroke-width="8"
        stroke="${COLORS[band]}" stroke-dasharray="${circumference}" stroke-dashoffset="${circumference}"></circle>
    </svg>
    <div class="num" style="color:${COLORS[band]}">${score}</div>`;
  el.setAttribute("role", "img");
  el.setAttribute("aria-label", `Risk score ${score} out of 100 (${band})`);
  // Next frame, so the CSS transition animates from empty to the score.
  requestAnimationFrame(() => {
    el.querySelector(".value").style.strokeDashoffset = String(circumference * (1 - score / 100));
  });
}

/** Render reasons as a list. textContent (never innerHTML) for API text: no XSS. */
export function renderReasons(ul, reasons, limit = 4) {
  ul.replaceChildren();
  for (const reason of topReasons(reasons, limit)) {
    const li = document.createElement("li");
    const dot = document.createElement("span");
    dot.className = `dot ${reason.severity}`;
    const body = document.createElement("div");
    const text = document.createElement("div");
    text.textContent = reason.message;
    const src = document.createElement("div");
    src.className = "src";
    src.textContent = reason.source === "model" ? "machine learning" : reason.source;
    body.append(text, src);
    li.append(dot, body);
    ul.append(li);
  }
}

export function setVerdictPill(el, score) {
  const band = bandFor(score);
  el.className = `pill ${band}`;
  el.textContent = band === "phishing" ? "Likely phishing" : band === "suspicious" ? "Suspicious" : "Looks safe";
}
