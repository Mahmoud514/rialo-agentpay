import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import { test } from "node:test";
import pg from "pg";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";

import { route } from "../../functions/_lib/auth/router.js";
import { handleMe } from "../../functions/_lib/auth/me.js";
import { handleOpenTasks } from "../../functions/_lib/tasks/open-tasks.js";
import { createAgentReadHandlers } from "../../functions/_lib/agents/read-agents.js";
import { createLeaderboardHandlers } from "../../functions/_lib/agents/leaderboard.js";
import { createTaskReadHandlers } from "../../functions/_lib/tasks/read-task.js";
import { createPgStore } from "./pg-store.mjs";
import {
  eip191Hash,
  normalizeEvmAddress,
} from "../../functions/_lib/auth/wallet.js";
import { bytesToHex } from "../../functions/_lib/auth/bytes.js";

const ORIGIN = "https://app.example";
const nativeFetch = globalThis.fetch;

const BASE_SCHEMA = `
CREATE TABLE IF NOT EXISTS schema_migrations (
  version BIGINT PRIMARY KEY,
  applied_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  session_id TEXT PRIMARY KEY,
  user_id BIGINT NOT NULL,
  login TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  expires_at BIGINT
);
CREATE TABLE IF NOT EXISTS user_wallets (
  user_id BIGINT PRIMARY KEY,
  pubkey TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tasks_pg (
  task_id TEXT PRIMARY KEY,
  owner_user_id BIGINT,
  worker_id BIGINT,
  owner_name TEXT,
  worker_name TEXT,
  title TEXT,
  reward_rlo DOUBLE PRECISION,
  created_at BIGINT DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'open'
);
ALTER TABLE tasks_pg ADD COLUMN IF NOT EXISTS worker_id BIGINT;
ALTER TABLE tasks_pg ADD COLUMN IF NOT EXISTS owner_name TEXT;
ALTER TABLE tasks_pg ADD COLUMN IF NOT EXISTS worker_name TEXT;
ALTER TABLE tasks_pg ADD COLUMN IF NOT EXISTS title TEXT;
ALTER TABLE tasks_pg ADD COLUMN IF NOT EXISTS reward_rlo DOUBLE PRECISION;
ALTER TABLE tasks_pg ADD COLUMN IF NOT EXISTS created_at BIGINT DEFAULT 0;
CREATE TABLE IF NOT EXISTS agents (
  agent_id TEXT PRIMARY KEY,
  schema_version INTEGER NOT NULL DEFAULT 1,
  owner_user_id BIGINT NOT NULL,
  name TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'draft',
  wallet_address TEXT,
  auth_public_key TEXT,
  created_at BIGINT NOT NULL DEFAULT 0,
  updated_at BIGINT NOT NULL DEFAULT 0
);
ALTER TABLE agents ADD COLUMN IF NOT EXISTS schema_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'draft';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS wallet_address TEXT;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS auth_public_key TEXT;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS created_at BIGINT NOT NULL DEFAULT 0;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS updated_at BIGINT NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS payment_intents (
  agent_id UUID NOT NULL,
  idempotency_key TEXT NOT NULL,
  state TEXT NOT NULL,
  amount_kelvin BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  PRIMARY KEY (agent_id, idempotency_key)
);
`;

function url() {
  return fs.readFileSync("/tmp/g1154-pg-url", "utf8").trim();
}

function sign(message, privateKey) {
  const signature = secp256k1.sign(eip191Hash(message), privateKey);
  const bytes = new Uint8Array(65);
  bytes.set(signature.toCompactRawBytes());
  bytes[64] = signature.recovery + 27;
  return bytesToHex(bytes);
}

function addressForPrivateKey(privateKey) {
  const publicKey = secp256k1.getPublicKey(privateKey, false);
  return normalizeEvmAddress(`0x${bytesToHex(keccak_256(publicKey.slice(1)).slice(-20))}`);
}

function cookieFrom(response) {
  const raw = response.headers.get("set-cookie");
  assert.ok(raw, "expected session cookie");
  return raw.split(";")[0];
}

async function requestJson(base, path, { method = "GET", body, cookie } = {}) {
  const headers = { origin: ORIGIN };
  if (body) headers["content-type"] = "application/json";
  if (cookie) headers.cookie = cookie;
  const response = await nativeFetch(`${base}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await response.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* non-JSON */ }
  return { status: response.status, headers: response.headers, json, text };
}

async function startHarness(store) {
  const agentRead = createAgentReadHandlers({
    createStore: () => store,
    now: () => 1000,
  });
  const leaderboardRead = createLeaderboardHandlers({
    createStore: () => store,
    now: () => 1000,
  });
  const taskRead = createTaskReadHandlers({
    createStore: () => store,
    now: () => 1000,
  });
  const server = http.createServer(async (req, res) => {
    try {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const body = chunks.length ? Buffer.concat(chunks) : undefined;
      const url = new URL(req.url, ORIGIN);
      const request = new Request(url, {
        method: req.method,
        headers: req.headers,
        body: req.method === "GET" || req.method === "HEAD" ? undefined : body,
      });
      let response;
      if (url.pathname.startsWith("/auth/")) {
        response = await route(request, store, { now: () => 1000, secure: false });
      } else if (url.pathname === "/api/me") {
        response = await handleMe(request, store, { now: 1000 });
      } else if (url.pathname === "/api/tasks") {
        response = await taskRead.list({ request, env: {} });
      } else if (url.pathname === "/api/tasks/open") {
        response = await handleOpenTasks(request, store, { now: 1000 });
      } else if (url.pathname === "/api/agents") {
        response = await agentRead.list({ request, env: {} });
      } else if (url.pathname === "/api/agents/leaderboard") {
        response = await leaderboardRead.list({ request, env: {} });
      } else if (/^\/api\/agents\/[0-9a-f-]{36}$/i.test(url.pathname)) {
        response = await agentRead.one(
          { request, env: {} },
          url.pathname.split("/").pop(),
        );
      } else if (/^\/api\/tasks\/[^/]+$/.test(url.pathname) && !url.pathname.endsWith("/open")) {
        response = await taskRead.one(
          { request, env: {} },
          decodeURIComponent(url.pathname.split("/").pop()),
        );
      } else {
        response = new Response(JSON.stringify({ error: "TEST_HARNESS_ONLY" }), {
          status: 503,
          headers: { "content-type": "application/json" },
        });
      }
      res.statusCode = response.status;
      for (const [name, value] of response.headers) {
        if (name.toLowerCase() === "set-cookie") {
          const prior = res.getHeader("set-cookie") ?? [];
          res.setHeader("set-cookie", [...(Array.isArray(prior) ? prior : [prior]), value]);
        } else {
          res.setHeader(name, value);
        }
      }
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch {
      res.statusCode = 503;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ error: "TEST_HARNESS_UNAVAILABLE" }));
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  return { server, base: `http://127.0.0.1:${address.port}` };
}

async function prepareDb(client) {
  await client.query(BASE_SCHEMA);
  for (const file of [
    "migrations/0006_fair_review.sql",
    "migrations/0007_worker_auth.sql",
    "migrations/0008_wallet_provisioning.sql",
  ]) {
    await client.query(fs.readFileSync(file, "utf8"));
  }
}

test("actual HTTP Worker auth + /api/me over disposable PostgreSQL, with no Blitz backend", async () => {
  const client = new pg.Client({ connectionString: url() });
  await client.connect();
  await prepareDb(client);
  await client.query("TRUNCATE sessions, wallet_nonces, auth_identities, auth_rate_limits, user_wallets, tasks_pg, agents, payment_intents");
  await client.query(
    `INSERT INTO tasks_pg
       (task_id, owner_user_id, worker_id, owner_name, worker_name, title,
        reward_rlo, created_at, status)
     VALUES ('task-open-1', 900, NULL, 'owner', '', 'Open task', 0.1, 100, 'open')`,
  );

  const store = createPgStore(url());
  const { server, base } = await startHarness(store);
  const originalFetch = globalThis.fetch;
  let blitzCalls = 0;
  globalThis.fetch = async () => {
    blitzCalls += 1;
    throw new Error("Blitz backend is intentionally down");
  };

  try {
    const privateKey = secp256k1.utils.randomPrivateKey();
    const address = addressForPrivateKey(privateKey);

    const nonce = await requestJson(base, "/auth/wallet/nonce", {
      method: "POST",
      body: { address },
    });
    assert.equal(nonce.status, 200);
    assert.equal(nonce.json.success, true);

    const verify = await requestJson(base, "/auth/wallet/verify", {
      method: "POST",
      body: {
        address,
        nonce: nonce.json.nonce,
        signature_hex: sign(nonce.json.message, privateKey),
      },
    });
    assert.equal(verify.status, 200);
    assert.equal(verify.json.success, true);
    const cookie = cookieFrom(verify);

    const me = await requestJson(base, "/api/me", { cookie });
    assert.equal(me.status, 200);
    assert.equal(me.json.logged_in, true);
    assert.equal(me.json.wallet_status, "no_wallet");
    assert.equal(me.json.balance_status, "no_wallet");
    assert.equal(blitzCalls, 0, "/api/me must not call Blitz");

    const agentId = "33333333-3333-4333-8333-333333333333";
    await client.query(
      `INSERT INTO agents
         (agent_id, schema_version, owner_user_id, name, status,
          wallet_address, auth_public_key, created_at, updated_at)
       VALUES ($1::uuid, 1, $2::bigint, 'owned agent', 'active', 'pub', NULL, 100, 101)`,
      [agentId, verify.json.user.id],
    );
    const agents = await requestJson(base, "/api/agents", { cookie });
    assert.equal(agents.status, 200);
    assert.equal(agents.json.success, true);
    assert.equal(agents.json.agents.length, 1);
    assert.equal(agents.json.agents[0].agent_id, agentId);
    assert.equal(agents.json.agents[0].owner_user_id, Number(verify.json.user.id));
    assert.equal(blitzCalls, 0, "GET /api/agents must not call Blitz");

    await client.query(
      `INSERT INTO payment_intents
         (agent_id, idempotency_key, state, amount_kelvin, updated_at)
       VALUES ($1::uuid, 'intent-1', 'confirmed', 1000000000, 150)`,
      [agentId],
    );
    const leaderboard = await requestJson(base, "/api/agents/leaderboard", { cookie });
    assert.equal(leaderboard.status, 200);
    assert.equal(leaderboard.json.total, 1);
    assert.equal(leaderboard.json.agents[0].confirmed_payment_count, 1);
    assert.equal(leaderboard.json.agents[0].confirmed_payment_volume_rlo, 1);
    assert.equal(blitzCalls, 0, "leaderboard must not call Blitz");

    const ownedAgent = await requestJson(base, `/api/agents/${agentId}`, { cookie });
    assert.equal(ownedAgent.status, 200);
    assert.equal(ownedAgent.json.agent.name, "owned agent");
    const foreignAgent = await requestJson(
      base,
      "/api/agents/44444444-4444-4444-8444-444444444444",
      { cookie },
    );
    assert.equal(foreignAgent.status, 404);
    assert.equal(blitzCalls, 0, "agent reads must not call Blitz");

    const openTask = await requestJson(base, "/api/tasks/task-open-1");
    assert.equal(openTask.status, 200);
    assert.equal(openTask.json.task.task_id, "task-open-1");
    const missingTask = await requestJson(base, "/api/tasks/missing-task");
    assert.equal(missingTask.status, 404);
    assert.equal(blitzCalls, 0, "task detail must not call Blitz");

    const openTasks = await requestJson(base, "/api/tasks/open");
    assert.equal(openTasks.status, 200);
    assert.equal(openTasks.json.count, 1);
    assert.equal(openTasks.json.tasks[0].task_id, "task-open-1");
    assert.equal(openTasks.json.tasks[0].reward_rlo, 0.1);
    assert.equal(blitzCalls, 0, "GET /api/tasks/open must not call Blitz");

    await client.query(
      "INSERT INTO user_wallets (user_id, pubkey) VALUES ($1::bigint, $2)",
      [verify.json.user.id, "RialoTestPublicAddress"],
    );
    const meWithWallet = await requestJson(base, "/api/me", { cookie });
    assert.equal(meWithWallet.status, 200);
    assert.equal(meWithWallet.json.wallet_status, "ready");
    assert.equal(meWithWallet.json.wallet_address, "RialoTestPublicAddress");
    assert.equal(meWithWallet.json.balance_status, "unavailable");

    const logout = await requestJson(base, "/auth/logout", {
      method: "POST",
      cookie,
      body: {},
    });
    assert.equal(logout.status, 200);

    const afterLogout = await requestJson(base, "/api/me", { cookie });
    assert.equal(afterLogout.json.logged_in, false);

    const expired = await requestJson(base, "/auth/wallet/nonce", {
      method: "POST",
      body: { address },
    });
    assert.equal(expired.status, 200);
    const expiredVerify = await requestJson(base, "/auth/wallet/verify", {
      method: "POST",
      body: {
        address,
        nonce: expired.json.nonce,
        signature_hex: sign(expired.json.message, privateKey),
      },
    });
    const expiredCookie = cookieFrom(expiredVerify);
    await client.query(
      `UPDATE sessions SET expires_at = 999 WHERE session_hash IS NOT NULL AND session_id = $1`,
      [expiredCookie.split("=")[1]],
    );
    const expiredMe = await requestJson(base, "/api/me", { cookie: expiredCookie });
    assert.equal(expiredMe.json.logged_in, false);

    // Legacy raw-only session compatibility during the transition.
    await client.query(
      `INSERT INTO sessions (session_id, session_hash, user_id, login, created_at, expires_at, auth_method, csrf_hash)
       VALUES ('legacy-raw-token', NULL, 987654321, 'legacy-user', 1000, 2000, NULL, NULL)`,
    );
    const legacyMe = await requestJson(base, "/api/me", {
      cookie: "agentpay_session=legacy-raw-token",
    });
    assert.equal(legacyMe.status, 200);
    assert.equal(legacyMe.json.logged_in, true);
    assert.equal(legacyMe.json.user.id, "987654321");

    // Limits of this harness: payment routes and task mutations are not
    // implemented here. They must remain explicitly tested backend surfaces.
    const tasks = await requestJson(base, "/api/tasks", { cookie });
    assert.equal(tasks.status, 200);
    assert.equal(tasks.json.count, 1);
    assert.equal(tasks.json.tasks[0].task_id, "task-open-1");
    assert.equal(blitzCalls, 0, "task list must not call Blitz");
  } finally {
    globalThis.fetch = originalFetch;
    await store.close();
    await new Promise((resolve) => server.close(resolve));
    await client.end();
  }
});
