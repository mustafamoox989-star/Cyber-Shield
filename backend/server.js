"use strict";

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { checkDomain, getStatus: getThreatIntelStatus } = require("./threat-intel");
const { analyzeUrl } = require("./risk-engine");

const app = express();
const PORT = process.env.PORT || 3000;

const allowedOrigins = new Set([
  "https://cyber-shield-173b8.web.app",
  "https://cyber-shield-173b8.firebaseapp.com",
  "http://localhost:5000",
  "http://localhost:5002",
  "http://127.0.0.1:5000",
  "http://127.0.0.1:5002"
]);

app.disable("x-powered-by");
app.use(helmet());
app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.has(origin)) return callback(null, true);
    return callback(new Error("Origin not allowed by Cyber Shield API."));
  },
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type"]
}));
app.use(express.json({ limit: "10kb" }));

const scanLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { success: false, error: "Too many scan requests. Please wait a minute." }
});

app.get("/", (_req, res) => {
  res.json({ success: true, name: "Cyber Shield Backend", status: "ACTIVE", version: "3.3.0" });
});

app.get("/api/health", (_req, res) => {
  const intel = getThreatIntelStatus();
  res.json({
    success: true,
    message: "Cyber Shield Backend is running",
    version: "3.3.0",
    threatIntelligence: intel.available ? "READY" : "LOADING_OR_UNAVAILABLE",
    threatDomainsLoaded: intel.domainCount,
    threatFeedUpdatedAt: intel.lastUpdated
  });
});

app.post("/api/scan", scanLimiter, (req, res) => {
  try {
    const input = String(req.body && req.body.url || "").trim();
    if (!input || input.length > 2048 || /\s/.test(input)) {
      return res.status(400).json({ success: false, error: "Please provide a valid website URL." });
    }

    const normalized = /^https?:\/\//i.test(input) ? input : "https://" + input;
    let parsed;
    try {
      parsed = new URL(normalized);
    } catch {
      return res.status(400).json({ success: false, error: "Please enter a valid website URL." });
    }

    if (!["http:", "https:"].includes(parsed.protocol) ||
        !parsed.hostname || !parsed.hostname.includes(".") ||
        parsed.username || parsed.password ||
        ![80, 443].includes(Number(parsed.port || (parsed.protocol === "https:" ? 443 : 80)))) {
      return res.status(400).json({ success: false, error: "Only valid public HTTP and HTTPS website URLs are supported." });
    }

    const threatIntelligence = checkDomain(parsed.hostname);
    const riskAnalysis = analyzeUrl(parsed.href, threatIntelligence);

    return res.json({ success: true, url: parsed.href, threatIntelligence, riskAnalysis });
  } catch (error) {
    console.error("[Scan] Error:", error);
    return res.status(500).json({ success: false, error: "The security engine could not complete the scan." });
  }
});

app.use((error, _req, res, _next) => {
  console.error("[API]", error.message);
  res.status(400).json({ success: false, error: error.message || "Bad request." });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log("----------------------------------");
  console.log(" CYBER SHIELD BACKEND 3.3.0");
  console.log("----------------------------------");
  console.log(`Server running on port ${PORT}`);
  console.log("Risk Engine: ACTIVE");
  console.log("Status: ACTIVE");
});
