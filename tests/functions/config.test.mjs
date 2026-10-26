import test from "node:test";
import assert from "node:assert/strict";
import { validateConfig } from "../../scripts/check-functions-config.mjs";

test("static-only mode does not require a backend", () => {
  assert.equal(validateConfig({ FUNCTIONS_STATIC_ONLY: "1" }).ok, true);
});

test("proxy mode requires a valid https BACKEND", () => {
  assert.equal(validateConfig({}).ok, false);
  assert.equal(validateConfig({ BACKEND: "http://example.com" }).ok, false);
  assert.equal(validateConfig({ BACKEND: "https://example.com/path" }).ok, false);
  assert.equal(validateConfig({ BACKEND: "https://example.com" }).ok, true);
});

test("worker auth and neon tasks require DATABASE_URL", () => {
  const backend = "https://example.com";
  assert.equal(validateConfig({ BACKEND: backend, AUTH_MODE: "worker" }).ok, false);
  assert.equal(validateConfig({ BACKEND: backend, TASKS_MODE: "neon" }).ok, false);
  assert.equal(
    validateConfig({ BACKEND: backend, AUTH_MODE: "worker", DATABASE_URL: "postgres://test" }).ok,
    true,
  );
});

test("unknown modes fail closed without echoing values", () => {
  const result = validateConfig({ BACKEND: "https://example.com", AUTH_MODE: "bogus" });
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((name) => name.startsWith("AUTH_MODE")));
  assert.ok(!JSON.stringify(result).includes("bogus"));
});
