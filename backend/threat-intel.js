"use strict";

const FEED_URL = "https://raw.githubusercontent.com/PhishIndex/phishindex-blocklist/main/Data/Malicious%20Domains/txt/phishindex_domains.txt";
const REFRESH_INTERVAL = 2 * 60 * 60 * 1000;

let maliciousDomains = new Set();
let lastUpdated = null;
let feedAvailable = false;
let lastError = null;

async function refreshThreatList() {
  try {
    const response = await fetch(FEED_URL, { signal: AbortSignal.timeout(15000) });
    if (!response.ok) throw new Error(`Feed request failed: ${response.status}`);

    const body = await response.text();
    const next = new Set();
    for (const line of body.split(/\r?\n/)) {
      const value = line.trim().toLowerCase();
      if (!value || value.startsWith("#")) continue;
      try {
        const host = new URL(value.includes("://") ? value : `https://${value}`).hostname.toLowerCase();
        if (host.includes(".") && !host.includes("..")) next.add(host);
      } catch {}
    }
    if (!next.size) throw new Error("Threat feed contained no valid domains.");

    maliciousDomains = next;
    lastUpdated = new Date().toISOString();
    feedAvailable = true;
    lastError = null;
    console.log(`[Threat Intel] Loaded ${next.size} domains.`);
  } catch (error) {
    lastError = error.message;
    console.error("[Threat Intel] Refresh failed:", error.message);
  }
}

function checkDomain(hostname) {
  if (!feedAvailable) {
    return {
      checked: false,
      isMalicious: false,
      status: "FEED_UNAVAILABLE",
      message: "Threat intelligence feed is unavailable. Heuristic analysis was still performed."
    };
  }

  const host = String(hostname || "").toLowerCase();
  const match = [...maliciousDomains].some(domain => host === domain || host.endsWith("." + domain));
  return {
    checked: true,
    isMalicious: match,
    status: match ? "MALICIOUS" : "NOT_LISTED",
    source: "PhishIndex Threat Blocklist",
    lastUpdated
  };
}

function getStatus() {
  return {
    available: feedAvailable,
    domainCount: maliciousDomains.size,
    lastUpdated,
    lastError
  };
}

refreshThreatList();
const timer = setInterval(refreshThreatList, REFRESH_INTERVAL);
timer.unref();

module.exports = { checkDomain, refreshThreatList, getStatus };
