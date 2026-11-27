"use strict";

const API_BASE = "https://cyber-shield-api-oym2.onrender.com";
const HISTORY_KEY = "cyberShieldHistory";
const $ = id => document.getElementById(id);
let latestReport = null;

function normalizeInput(value) {
  const raw = String(value || "").trim();
  if (!raw || raw.length > 2048 || /\s/.test(raw)) throw new Error("Enter a valid website URL without spaces.");
  const url = new URL(/^https?:\/\//i.test(raw) ? raw : "https://" + raw);
  if (!["http:", "https:"].includes(url.protocol) || !url.hostname.includes(".") || url.username || url.password) {
    throw new Error("Only valid public HTTP and HTTPS website URLs are supported.");
  }
  return url.href;
}

function riskColor(level) {
  if (level === "CRITICAL" || level === "HIGH") return "#ff6475";
  if (level === "MEDIUM") return "#f5bd55";
  return "#4be0a5";
}

function getHistory() {
  try {
    const parsed = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch { return []; }
}

function saveHistory(record) {
  const history = [record, ...getHistory().filter(item => item.url !== record.url)].slice(0, 15);
  localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
  renderHistory();
}

function renderHistory() {
  const list = $("historyList");
  const history = getHistory();
  list.replaceChildren();
  if (!history.length) {
    const empty = document.createElement("p");
    empty.className = "empty";
    empty.textContent = "Your recent scans will appear here.";
    list.appendChild(empty);
    return;
  }
  history.forEach(item => {
    const row = document.createElement("div");
    row.className = "history-item";
    const url = document.createElement("span");
    url.className = "history-url";
    url.textContent = item.url;
    const meta = document.createElement("span");
    meta.className = "history-meta";
    meta.innerHTML = "";
    const score = document.createElement("strong");
    score.className = "history-score";
    score.style.color = riskColor(item.level);
    score.textContent = item.score + "/100 · " + item.level;
    const date = document.createElement("span");
    date.textContent = " · " + new Date(item.date).toLocaleString();
    meta.append(score, date);
    row.append(url, meta);
    row.addEventListener("click", () => { $("urlInput").value = item.url; });
    list.appendChild(row);
  });
}

function renderReport(url, analysis, intel) {
  const color = riskColor(analysis.level);
  $("scoreValue").textContent = analysis.score;
  $("scoreRing").style.borderColor = color;
  $("riskLevel").textContent = analysis.level === "CRITICAL" ? "VERY HIGH RISK" : analysis.level + " RISK";
  $("riskLevel").style.color = color;
  $("riskSummary").textContent = analysis.disclaimer || "Risk assessment based on available indicators.";
  $("scannedUrl").textContent = url;
  $("meterFill").style.width = analysis.score + "%";
  $("meterFill").style.background = color;
  $("intelStatus").textContent = intel?.isMalicious ? "Known malicious domain" : intel?.checked ? "Not found in feed" : "Feed unavailable";
  $("intelSource").textContent = intel?.source || intel?.message || "PhishIndex threat intelligence";
  $("factorCount").textContent = (analysis.factors || []).length + " detected";
  const list = $("findings");
  list.replaceChildren();
  const factors = analysis.factors || [];
  if (!factors.length) {
    const li = document.createElement("li");
    li.textContent = "No indicators were detected by the available checks. This does not prove the site is safe.";
    list.appendChild(li);
  } else {
    factors.forEach(factor => {
      const li = document.createElement("li");
      li.textContent = factor.description + " (+" + factor.points + " points)";
      list.appendChild(li);
    });
  }
  $("disclaimer").textContent = "A low score is not a guarantee of safety. The scanner uses URL heuristics and a threat-intelligence feed; newly created or unlisted phishing sites may not be detected.";
  $("result").hidden = false;
  latestReport = { url, score: analysis.score, level: analysis.level, factors, intel };
}

async function scanURL(value) {
  $("errorBox").hidden = true;
  $("result").hidden = true;
  $("loading").hidden = false;
  $("scanBtn").disabled = true;
  let url;
  try {
    url = normalizeInput(value);
    const response = await fetch(API_BASE + "/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(30000)
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || !data.success) throw new Error(data.error || "The scan service could not process this URL.");
    if (!data.riskAnalysis) throw new Error("The backend is still updating. Please try again in a minute.");
    renderReport(data.url || url, data.riskAnalysis, data.threatIntelligence);
    saveHistory({ url: data.url || url, score: data.riskAnalysis.score, level: data.riskAnalysis.level, date: new Date().toISOString() });
  } catch (error) {
    $("errorBox").textContent = error.name === "TimeoutError" ? "The scan service took too long to respond. Please try again." : error.message || "Unable to complete the scan.";
    $("errorBox").hidden = false;
  } finally {
    $("loading").hidden = true;
    $("scanBtn").disabled = false;
  }
}

$("scanForm").addEventListener("submit", event => {
  event.preventDefault();
  scanURL($("urlInput").value);
});

$("clearHistory").addEventListener("click", () => {
  localStorage.removeItem(HISTORY_KEY);
  renderHistory();
});

$("copyReport").addEventListener("click", async () => {
  if (!latestReport) return;
  const report = [
    "CYBER SHIELD SCAN REPORT",
    "URL: " + latestReport.url,
    "Risk: " + latestReport.score + "/100 (" + latestReport.level + ")",
    "Threat feed match: " + Boolean(latestReport.intel?.isMalicious),
    "Indicators:",
    ...(latestReport.factors || []).map(item => "- " + item.description)
  ].join("\n");
  try {
    await navigator.clipboard.writeText(report);
    $("copyReport").textContent = "Copied!";
    setTimeout(() => { $("copyReport").textContent = "Copy scan report"; }, 1800);
  } catch {
    $("errorBox").textContent = "Could not copy automatically. Please select and copy the report manually.";
    $("errorBox").hidden = false;
  }
});

async function checkApi() {
  const status = $("apiStatus");
  try {
    const response = await fetch(API_BASE + "/api/health", { signal: AbortSignal.timeout(10000) });
    if (!response.ok) throw new Error();
    const data = await response.json();
    status.innerHTML = "<i></i> API " + (data.version || "online");
    status.querySelector("i").style.background = "#4be0a5";
  } catch {
    status.innerHTML = "<i></i> API unavailable";
    status.querySelector("i").style.background = "#ff6475";
  }
}

renderHistory();
checkApi();