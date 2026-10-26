import assert from "node:assert/strict";
import { test } from "node:test";
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { createD1Store } from "../../functions/_lib/auth/d1-store.js";

// Minimal D1 adapter over Node's built-in SQLite. It validates the SQL used by
// the D1 store without a network or a Cloudflare binding.
function d1(sqlite) {
  return {
    prepare(sql) {
      return {
        args: [],
        bind(...args) {
          this.args = args;
          return this;
        },
        first() {
          return sqlite.prepare(sql).get(...this.args) ?? null;
        },
        all() {
          return { results: sqlite.prepare(sql).all(...this.args) };
        },
        run() {
          const result = sqlite.prepare(sql).run(...this.args);
          return { meta: { changes: Number(result.changes ?? 0) } };
        },
      };
    },
  };
}

function newStore() {
  const sqlite = new DatabaseSync(":memory:");
  sqlite.exec(readFileSync(new URL("../../migrations/0009_d1_auth.sql", import.meta.url), "utf8"));
  sqlite.exec(readFileSync(new URL("../../migrations/0010_d1_app.sql", import.meta.url), "utf8"));
  return { sqlite, store: createD1Store(d1(sqlite)) };
}

test("D1 store consumes a nonce exactly once and binds it to its purpose", async () => {
  const { store } = newStore();
  await store.createNonce({
    nonce_hash: "hash-1",
    address: "0x0000000000000000000000000000000000000001",
    purpose: "login",
    user_id: null,
    message: "template",
    domain: "http://localhost:8800",
    chain_id: null,
    issued_at: 100,
    expires_at: 200,
  });
  const first = await store.consumeNonce("hash-1", 150);
  assert.equal(first.purpose, "login");
  assert.equal(await store.consumeNonce("hash-1", 150), null);
  assert.equal(await store.consumeNonce("hash-1", 250), null);
});

test("D1 store persists identity, session, wallet and provisioning projections", async () => {
  const { store } = newStore();
  const identity = await store.insertIdentity({
    provider: "wallet",
    subject: "0xabc",
    user_id: 42,
    login: "0xabc",
    verified_at: 10,
  });
  assert.equal(identity.user_id, "42");
  assert.equal(await store.insertIdentity({
    provider: "wallet",
    subject: "0xabc",
    user_id: 42,
    login: "0xabc",
    verified_at: 10,
  }), null);
  assert.equal((await store.findIdentity("wallet", "0xabc")).user_id, "42");
  assert.equal(await store.hasUserActivity(42), false);

  const clock = Math.floor(Date.now() / 1000);
  await store.createSession({
    session_id: "raw-session",
    session_hash: "hash-session",
    user_id: 42,
    login: "0xabc",
    created_at: clock,
    expires_at: clock + 500,
    auth_method: "wallet",
    csrf_hash: "csrf",
  });
  assert.equal(await store.hasUserActivity(42), true);
  const byHash = await store.getSession({ tokenHash: "hash-session", rawToken: "raw-session", now: clock + 1 });
  assert.equal(byHash.session_id, "raw-session");
  assert.equal(await store.getSession({ tokenHash: "missing", rawToken: "raw-session", now: clock + 1 }), null);
  await store.createSession({
    session_id: "legacy-raw",
    session_hash: null,
    user_id: 42,
    login: "0xabc",
    created_at: clock,
    expires_at: clock + 500,
    auth_method: "wallet",
    csrf_hash: "csrf",
  });
  const byRaw = await store.getSession({ tokenHash: "missing", rawToken: "legacy-raw", now: clock + 1 });
  assert.equal(byRaw.session_id, "legacy-raw");
  assert.equal(await store.getSession({ tokenHash: "hash-session", rawToken: "raw-session", now: clock + 600 }), null);

  await store.setSessionCsrf("raw-session", "csrf-2");
  assert.equal((await store.getSession({ tokenHash: "hash-session", rawToken: "raw-session", now: clock + 1 })).csrf_hash, "csrf-2");
  await store.deleteSession("raw-session");
  assert.equal(await store.getSession({ tokenHash: "hash-session", rawToken: "raw-session", now: clock + 1 }), null);

  assert.equal((await store.hitRateLimit("ip", 60, 1)).limited, false);
  assert.equal((await store.hitRateLimit("ip", 60, 1)).limited, true);
  assert.equal(await store.getProvisioning(42), null);
  assert.equal(await store.enqueueProvisioning(42, 10), true);
  assert.equal(await store.enqueueProvisioning(42, 10), false);
  assert.equal((await store.getProvisioning(42)).state, "pending");
  assert.equal(await store.getUserWallet(42), null);
});

test("D1 app projection supports owner agents, policy and task lifecycle", async () => {
  const { store } = newStore();
  const clock = Math.floor(Date.now() / 1000);
  const agent = await store.createAgent("42", "11111111-1111-4111-8111-111111111111", "Test Agent", clock);
  assert.equal(agent.status, "draft");
  assert.equal((await store.listAgents("42")).length, 1);
  assert.equal((await store.getAgent("99", agent.agent_id)), null);
  await store.renameAgent("42", agent.agent_id, "Renamed", clock + 1);
  assert.equal((await store.getAgent("42", agent.agent_id)).name, "Renamed");
  assert.equal((await store.setAgentStatus("42", agent.agent_id, "active", clock + 2)).agent.status, "active");
  await store.setAgentPolicy("42", agent.agent_id, { allowed_actions: ["payment"] }, clock + 3);
  assert.deepEqual((await store.getAgentPolicy("42", agent.agent_id)).allowed_actions, ["payment"]);
  const task = await store.createTask({ task_id: "22222222-2222-4222-8222-222222222222", owner_user_id: "42", owner_name: "owner", agent_id: agent.agent_id, title: "Task", description: "d", acceptance_criteria: "a", reward_kelvin: 1000, created_at: clock });
  assert.equal(task.status, "open");
  assert.equal((await store.claimTask(task.task_id, "99", "worker", "A".repeat(32), clock + 4)).task.status, "inprogress");
  assert.equal((await store.claimTask(task.task_id, "100", "worker2", "B".repeat(32), clock + 5)).conflict, true);
  assert.equal((await store.submitTask(task.task_id, "99", "https://example.test", "done", [], clock + 6)).task.status, "underreview");
  assert.equal((await store.reviewTask(task.task_id, "42", "reject", "no", clock + 7)).task.status, "rejected");
});
