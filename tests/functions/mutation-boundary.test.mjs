import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

const root = path.resolve(import.meta.dirname, "../..");
const functions = (() => {
  const walk = (dir) =>
    fs
      .readdirSync(dir, { withFileTypes: true })
      .flatMap((e) => {
        const p = path.join(dir, e.name);
        if (e.isDirectory()) return walk(p);
        return e.isFile() && /\.(js|ts)$/.test(e.name) ? [fs.readFileSync(p, "utf8")] : [];
      });
  return walk(path.join(root, "functions")).join("\n");
})();

test("task mutations remain behind the trusted backend boundary", () => {
  for (const marker of [
    "INSERT INTO tasks",
    "UPDATE tasks",
    "DELETE FROM tasks",
    "/cancel",
    "/claim",
    "/submit",
    "/review",
  ]) {
    assert.equal(functions.includes(marker), false, `unexpected Worker task mutation: ${marker}`);
  }
});

test("value movement and OAuth/recovery remain unowned by the Worker", () => {
  for (const marker of [
    "INSERT INTO payments",
    "UPDATE balances",
    "POST /api/faucet",
    "POST /api/payment",
    "/auth/github",
    "wallet-recover",
  ]) {
    assert.equal(
      functions.includes(marker),
      false,
      `unexpected Worker-owned value/identity marker: ${marker}`,
    );
  }
});
