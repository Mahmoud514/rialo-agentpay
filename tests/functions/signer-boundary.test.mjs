import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

const root = path.resolve(import.meta.dirname, "../..");

function readTree(dir) {
  return fs
    .readdirSync(dir, { withFileTypes: true })
    .flatMap((entry) => {
      const p = path.join(dir, entry.name);
      if (entry.isDirectory()) return readTree(p);
      if (entry.isFile() && /\.(js|ts)$/.test(entry.name)) return [fs.readFileSync(p, "utf8")];
      return [];
    })
    .join("\n");
}

test("Worker functions contain no signer ceremony secrets or user-wallet create call", () => {
  const worker = readTree(path.join(root, "functions"));
  for (const forbidden of [
    "AGENTPAY_SIGNER_ADMIN_SECRET",
    "AGENTPAY_SIGNER_USER_CREATE_SECRET",
    "AGENTPAY_USER_WALLET_VERSION",
    "admin_ceremony_proof",
    "intro_proof",
    "/user/wallet",
  ]) {
    assert.equal(
      worker.includes(forbidden),
      false,
      `Worker must not contain signer-only ceremony material: ${forbidden}`,
    );
  }
});

test("V8 boundary remains explicitly local and opt-in", () => {
  const server = fs.readFileSync(path.join(root, "src/bin/server.rs"), "utf8");
  assert.match(server, /AGENTPAY_WALLET_PROVISIONING/);
  assert.match(server, /V8LocalSigner/);
  assert.doesNotMatch(server, /TxSigner::User/);
});
