import assert from "node:assert/strict";
import { test } from "node:test";

import { MemoryAuthStore } from "../../functions/_lib/auth/memory-store.js";
import { createMeHandler } from "../../functions/_lib/auth/me.js";
import { SESSION_COOKIE, sessionHash } from "../../functions/_lib/auth/session.js";

const ORIGIN = "https://app.example";

function request(cookie) {
  const headers = cookie ? { cookie: `${SESSION_COOKIE}=${cookie}` } : {};
  return new Request(`${ORIGIN}/api/me`, { method: "GET", headers });
}

function handlerFor(store) {
  return createMeHandler({
    createStore: () => store,
    now: () => 1_000,
  });
}

test("logged-out /api/me does not touch the database", async () => {
  const store = new MemoryAuthStore();
  const response = await handlerFor(store)({ request: request(), env: {} });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.logged_in, false);
  assert.equal(body.wallet_address, null);
  assert.equal(store.calls.length, 0);
});

test("Worker-owned /api/me reads a hashed session and public wallet address without Blitz", async () => {
  const store = new MemoryAuthStore();
  store.sessions.set("session-token", {
    session_id: "session-token",
    session_hash: sessionHash("session-token"),
    user_id: "123",
    login: "0xabc",
    expires_at: 2_000,
    auth_method: "wallet",
    csrf_hash: null,
  });
  store.wallets.set("123", { pubkey: "RialoPublicAddress" });

  let fetched = false;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    fetched = true;
    throw new Error("Blitz must not be called by /api/me");
  };
  try {
    const response = await handlerFor(store)({
      request: request("session-token"),
      env: {},
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.logged_in, true);
    assert.equal(body.user.id, "123");
    assert.equal(body.wallet_address, "RialoPublicAddress");
    assert.equal(body.wallet_status, "ready");
    assert.equal(body.balance, null);
    assert.equal(body.balance_status, "unavailable");
    assert.equal(fetched, false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("a session can observe provisioning without a wallet and without calling Blitz", async () => {
  const store = new MemoryAuthStore();
  store.sessions.set("pending-session", {
    session_id: "pending-session",
    session_hash: sessionHash("pending-session"),
    user_id: "321",
    login: "0xdef",
    expires_at: 2_000,
    auth_method: "wallet",
    csrf_hash: null,
  });
  store.getProvisioning = async () => ({ state: "pending", updated_at: 1_234 });

  let fetched = false;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    fetched = true;
    throw new Error("Blitz must not be called by /api/me");
  };
  try {
    const response = await handlerFor(store)({
      request: request("pending-session"),
      env: {},
    });
    const body = await response.json();
    assert.equal(response.status, 200);
    assert.equal(body.logged_in, true);
    assert.equal(body.wallet_address, null);
    assert.equal(body.wallet_status, "provisioning");
    assert.equal(body.provisioning.state, "pending");
    assert.equal(fetched, false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("legacy raw-only sessions remain readable by /api/me", async () => {
  const store = new MemoryAuthStore();
  store.sessions.set("legacy-token", {
    session_id: "legacy-token",
    session_hash: null,
    user_id: "456",
    login: "legacy-user",
    expires_at: null,
    auth_method: null,
    csrf_hash: null,
  });

  const response = await handlerFor(store)({
    request: request("legacy-token"),
    env: {},
  });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.logged_in, true);
  assert.equal(body.user.login, "legacy-user");
  assert.equal(body.wallet_status, "no_wallet");
});

test("expired sessions are logged out", async () => {
  const store = new MemoryAuthStore();
  store.sessions.set("expired", {
    session_id: "expired",
    session_hash: null,
    user_id: "789",
    login: "expired",
    expires_at: 999,
    auth_method: null,
    csrf_hash: null,
  });

  const response = await handlerFor(store)({ request: request("expired"), env: {} });
  assert.equal((await response.json()).logged_in, false);
});

test("missing database configuration fails closed", async () => {
  const handler = createMeHandler({
    createStore: () => {
      throw new Error("missing DATABASE_URL");
    },
    now: () => 1_000,
  });
  const response = await handler({ request: request("token"), env: {} });
  assert.equal(response.status, 503);
  assert.equal((await response.json()).error.code, "AUTH_UNAVAILABLE");
});
