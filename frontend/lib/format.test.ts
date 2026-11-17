// Run with `npm test` (Node 24 runs TypeScript directly by stripping types).
import assert from "node:assert/strict";
import { test } from "node:test";

import { age, bandFor, compact, easeOut, featureValue, ms, pct, timeAgo } from "./format.ts";

test("bands match the backend", () => {
  assert.equal(bandFor(39), "safe");
  assert.equal(bandFor(40), "suspicious");
  assert.equal(bandFor(69), "suspicious");
  assert.equal(bandFor(70), "phishing");
});

test("number formatting", () => {
  assert.equal(pct(0.9012), "90.1%");
  assert.equal(pct(null), "–");
  assert.equal(ms(0.42), "0.42 ms");
  assert.equal(ms(0.004), "<0.01 ms");
  assert.equal(ms(12.4), "12 ms");
  assert.equal(ms(1530), "1.5 s");
  assert.equal(compact(1284), "1,284");
  assert.equal(compact(12_900), "12.9K");
  assert.equal(featureValue(3), "3");
  assert.equal(featureValue(3.14159), "3.14");
});

test("ages and relative times", () => {
  assert.equal(age(1), "1 day");
  assert.equal(age(12), "12 days");
  assert.equal(age(400), "13 months");
  assert.equal(age(6978), "19 years");
  assert.equal(age(null), "unknown");
  const now = new Date("2026-11-17T12:00:00Z");
  assert.equal(timeAgo("2026-11-17T11:59:30Z", now), "30s ago");
  assert.equal(timeAgo("2026-11-17T09:00:00Z", now), "3h ago");
});

test("easing is clamped and monotonic", () => {
  assert.equal(easeOut(-1), 0);
  assert.equal(easeOut(2), 1);
  assert.ok(easeOut(0.25) < easeOut(0.5) && easeOut(0.5) < easeOut(0.75));
});
