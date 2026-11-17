// Sample result used when a page is opened with ?demo=1 (outside the
// extension, e.g. for README screenshots), so no chrome.* API is needed.
export const DEMO_RESULT = {
  url: "http://paypal.com.secure-login.verify-account.xyz/signin",
  normalized_url: "http://paypal.com.secure-login.verify-account.xyz/signin",
  domain: "verify-account.xyz",
  score: 100,
  verdict: "phishing",
  mode: "fast",
  reasons: [
    { id: "brand_in_host", source: "rule", severity: "high",
      message: "Mentions PayPal in the address, but the site is verify-account.xyz, not paypal.com" },
    { id: "model:suspicious_word_count", source: "model", severity: "high",
      message: "Uses words common in phishing: account, login, secure, signin, verify" },
    { id: "tld_in_subdomain", source: "rule", severity: "medium",
      message: "Starts like a familiar domain but really belongs to verify-account.xyz" },
    { id: "suspicious_tld", source: "rule", severity: "low",
      message: ".xyz is among the TLDs most abused for phishing" },
  ],
};

export const isDemo = () => new URLSearchParams(location.search).has("demo");
