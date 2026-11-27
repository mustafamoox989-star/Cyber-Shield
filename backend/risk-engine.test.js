"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { analyzeUrl } = require("./risk-engine");

test("ordinary HTTPS URL has low risk", () => {
  const result = analyzeUrl("https://www.wikipedia.org/", { isMalicious: false });
  assert.equal(result.level, "LOW");
  assert.ok(result.score < 30);
});

test("HTTP and suspicious URL indicators raise the score without claiming confirmed phishing", () => {
  const result = analyzeUrl("http://secure-login-account-verify-paypal.xyz/signin/password/update", { isMalicious: false });
  assert.ok(result.score >= 30);
  assert.ok(result.score < 85);
  assert.notEqual(result.level, "CRITICAL");
  assert.ok(result.factors.length >= 3);
});

test("known blocklisted domain receives critical risk", () => {
  const result = analyzeUrl("https://bad.example/", { isMalicious: true });
  assert.equal(result.score, 95);
  assert.equal(result.level, "CRITICAL");
});
