// Unit tests for the pure helpers (run: npm test, from the extension folder).
import assert from "node:assert/strict";
import { test } from "node:test";

import {
  DEFAULT_SETTINGS, bandFor, hostOf, isAllowlisted, isShortener, normalizeAllowEntry, shouldScan, topReasons,
} from "../lib/core.js";

const settings = { ...DEFAULT_SETTINGS, allowlist: ["example.com"] };

test("bands match the backend thresholds", () => {
  assert.equal(bandFor(0), "safe");
  assert.equal(bandFor(39), "safe");
  assert.equal(bandFor(40), "suspicious");
  assert.equal(bandFor(70), "phishing");
});

test("allowlist entries cover subdomains but not look-alike suffixes", () => {
  assert.ok(isAllowlisted("example.com", ["example.com"]));
  assert.ok(isAllowlisted("login.example.com", ["example.com"]));
  assert.ok(!isAllowlisted("badexample.com", ["example.com"]));   // not a subdomain
  assert.ok(!isAllowlisted("example.com.evil.xyz", ["example.com"]));
});

test("allowlist input is normalised", () => {
  assert.equal(normalizeAllowEntry("https://Login.Example.com/path?q=1"), "login.example.com");
  assert.equal(normalizeAllowEntry("*.example.com"), "example.com");
  assert.equal(normalizeAllowEntry("  EXAMPLE.com "), "example.com");
  assert.equal(normalizeAllowEntry("not a domain"), "");
  assert.equal(normalizeAllowEntry("localhost"), "");
});

test("only public web pages are scanned", () => {
  assert.ok(shouldScan("https://unknown-site.xyz/login", settings));
  assert.ok(!shouldScan("chrome://settings", settings));
  assert.ok(!shouldScan("chrome-extension://abc/warning.html", settings));
  assert.ok(!shouldScan("http://localhost:3100/", settings));
  assert.ok(!shouldScan("http://192.168.1.1/", settings));
  assert.ok(!shouldScan("http://127.0.0.1:8000/api/scan", settings));
  assert.ok(!shouldScan("https://www.example.com/", settings));       // allowlisted
  assert.ok(!shouldScan("not a url", settings));
});

test("hosts and shorteners", () => {
  assert.equal(hostOf("https://WWW.Example.COM./x"), "www.example.com");
  assert.equal(hostOf("garbage"), "");
  assert.ok(isShortener("bit.ly"));
  assert.ok(!isShortener("bitly.example"));
});

test("risky reasons come before informational ones", () => {
  const reasons = [
    { severity: "info", message: "old domain" },
    { severity: "high", message: "homoglyph" },
    { severity: "low", message: "tld" },
  ];
  assert.deepEqual(topReasons(reasons, 2).map((r) => r.message), ["homoglyph", "tld"]);
});
