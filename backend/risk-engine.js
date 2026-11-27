"use strict";

const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "is.gd", "rb.gy",
  "cutt.ly", "ow.ly", "shorturl.at", "buff.ly", "rebrand.ly"
]);
const HIGH_RISK_TLDS = new Set(["zip", "mov", "top", "click", "work", "buzz", "gq", "tk", "ml", "cf"]);
const SUSPICIOUS_TERMS = [
  "verify", "password", "credential", "wallet", "banking",
  "account-update", "secure-login", "signin", "confirm-identity",
  "payment-update", "recover-account"
];

function analyzeUrl(rawUrl, threatIntelligence) {
  const url = new URL(rawUrl);
  const host = url.hostname.toLowerCase().replace(/^www\./, "");
  const labels = host.split(".");
  const factors = [];
  let score = 0;

  const add = (points, code, description) => {
    score += points;
    factors.push({ code, points, description });
  };

  if (threatIntelligence && threatIntelligence.isMalicious) {
    add(95, "KNOWN_MALICIOUS_DOMAIN", "The domain appears in the connected phishing threat blocklist.");
  } else {
    if (url.protocol !== "https:") add(8, "NO_HTTPS", "The URL does not use HTTPS.");
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) add(28, "IP_HOST", "The website uses an IP address instead of a normal domain.");
    if (url.username || url.password) add(35, "URL_CREDENTIALS", "The URL contains user-information fields that can disguise its destination.");
    if (host.startsWith("xn--") || host.split(".").some(label => label.startsWith("xn--"))) {
      add(22, "PUNYCODE", "The domain uses Punycode, which can be used in look-alike domains.");
    }
    if (SHORTENERS.has(host)) add(12, "URL_SHORTENER", "The link uses a URL-shortening service, so its destination is obscured.");
    if (labels.length >= 5) add(8, "MANY_SUBDOMAINS", "The hostname contains an unusually large number of subdomains.");
    if (host.length > 45) add(6, "LONG_HOSTNAME", "The hostname is unusually long.");
    if ((host.match(/-/g) || []).length >= 3) add(8, "MANY_HYPHENS", "The hostname contains several hyphens.");
    if (HIGH_RISK_TLDS.has(labels[labels.length - 1])) add(7, "UNCOMMON_TLD", "The domain uses a top-level domain that warrants extra scrutiny.");

    const lower = url.href.toLowerCase();
    const matched = SUSPICIOUS_TERMS.filter(term => lower.includes(term));
    if (matched.length) add(Math.min(4 * matched.length, 16), "SUSPICIOUS_TERMS", "Suspicious URL wording: " + matched.join(", ") + ".");
    if (url.href.length > 120) add(5, "LONG_URL", "The complete URL is unusually long.");
  }

  score = Math.min(100, score);
  let level = "LOW";
  if (score >= 85) level = "CRITICAL";
  else if (score >= 60) level = "HIGH";
  else if (score >= 30) level = "MEDIUM";

  return {
    score,
    level,
    factors,
    disclaimer: score === 0
      ? "No indicators were detected by the available checks. This is not proof that the website is safe."
      : "This score reflects detected indicators, not a guarantee that the website is malicious."
  };
}

module.exports = { analyzeUrl };
