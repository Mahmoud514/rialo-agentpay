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

test("Worker task mutations are metadata-only and cannot approve value", () => {
  // The Cloudflare preview owns task metadata in D1, but approval is a
  // money-moving operation and must remain behind the isolated signer.
  assert.equal(functions.includes('PAYOUT_UNAVAILABLE'), true);
  assert.equal(functions.includes('INSERT INTO payment_intents'), false);
  assert.equal(functions.includes('status = \'paid\''), false);
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
