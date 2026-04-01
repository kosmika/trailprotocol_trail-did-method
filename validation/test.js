#!/usr/bin/env node

/**
 * TRAIL Protocol - DID Document Validator Tests
 *
 * Runs all fixtures and checks expected validation outcomes.
 *
 * Usage:
 *   node --test validation/test.js
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { validateDidDocument } = require("./did-document-validator");

const fixturesDir = path.join(__dirname, "fixtures");

const cases = [
  { file: "valid-did-document.json", valid: true },

  { file: "invalid-missing-id.json", valid: false },
  { file: "invalid-missing-controller.json", valid: false },
  { file: "invalid-bad-id-format.json", valid: false },
  { file: "invalid-missing-verification-method.json", valid: false },
  { file: "invalid-bad-key-material.json", valid: false },
  { file: "invalid-bad-service-endpoint.json", valid: false },
  { file: "invalid-bad-capability-delegation.json", valid: false },
  { file: "invalid-agent-missing-parent-org.json", valid: false },
];

function loadFixture(fileName) {
  const fullPath = path.join(fixturesDir, fileName);
  const raw = fs.readFileSync(fullPath, "utf8");
  return JSON.parse(raw);
}

test("all validation fixtures produce expected results", () => {
  for (const testCase of cases) {
    const doc = loadFixture(testCase.file);
    const result = validateDidDocument(doc);

    assert.equal(
      result.valid,
      testCase.valid,
      `${testCase.file}: expected valid=${testCase.valid}, got valid=${result.valid}. Errors: ${result.errors.join(" | ")}`
    );

    if (testCase.valid) {
      assert.equal(
        result.errors.length,
        0,
        `${testCase.file}: expected no errors, got ${result.errors.length}`
      );
    } else {
      assert.ok(
        result.errors.length > 0,
        `${testCase.file}: expected at least one validation error`
      );
    }
  }
});
