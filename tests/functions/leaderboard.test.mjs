import assert from "node:assert/strict";
import { test } from "node:test";

import {
  createLeaderboardHandlers,
  createLeaderboardMiddleware,
} from "../../functions/_lib/agents/leaderboard.js";

function request(path = "/api/agents/leaderboard", cookie = "session") {
  const headers = cookie ? { cookie: `agentpay_session=${cookie}` } : {};
  return new Request(`https://app.test${path}`, { method: "GET", headers });
}

function storeWith(rows) {
  return {
    calls: [],
    async getSession(args) {
      this.calls.push(["getSession", args.tokenHash]);
      return { user_id: "7", login: "owner", expires_at: 2_000 };
    },
    async getLeaderboard(userId) {
      this.calls.push(["getLeaderboard", userId]);
      return rows;
    },
  };
}

test("leaderboard is owner-scoped and returns the exact public row shape", async () => {
  const store = storeWith([
    {
      agent_id: "33333333-3333-4333-8333-333333333333",
      name: "agent",
      status: "active",
      total_intent_count: "4",
      confirmed_payment_count: "2",
      confirmed_payment_volume_kelvin: "2500000000",
      last_confirmed_at: "1700000000",
      pending_count: "1",
      failed_count: "0",
      unknown_count: "1",
      reconciled_count: "0",
    },
  ]);
  const handlers = createLeaderboardHandlers({ createStore: () => store, now: () => 1000 });
  const response = await handlers.list({ request: request(), env: {} });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.success, true);
  assert.equal(body.total, 1);
  assert.equal(body.order.includes("confirmed_payment_volume_kelvin DESC"), true);
  assert.deepEqual(body.agents[0], {
    agent_id: "33333333-3333-4333-8333-333333333333",
    name: "agent",
    status: "active",
    total_intent_count: 4,
    confirmed_payment_count: 2,
    confirmed_payment_volume_kelvin: 2_500_000_000,
    confirmed_payment_volume_rlo: 2.5,
    last_confirmed_at: 1_700_000_000,
    pending_count: 1,
    failed_count: 0,
    unknown_count: 1,
    reconciled_count: 0,
  });
  assert.deepEqual(store.calls[1], ["getLeaderboard", "7"]);
});

test("leaderboard requires a session and does not create a store when logged out", async () => {
  let created = 0;
  const handlers = createLeaderboardHandlers({
    createStore: () => {
      created += 1;
      return storeWith([]);
    },
  });
  const response = await handlers.list({ request: request("/api/agents/leaderboard", ""), env: {} });
  assert.equal(response.status, 401);
  assert.equal((await response.json()).error.code, "NOT_AUTHENTICATED");
  assert.equal(created, 0);
});

test("leaderboard never turns a store failure into a partial or fake success", async () => {
  const handlers = createLeaderboardHandlers({
    createStore: () => ({
      async getSession() {
        return { user_id: "7", login: "owner", expires_at: 2_000 };
      },
      async getLeaderboard() {
        throw new Error("postgres password must not leak");
      },
    }),
    now: () => 1000,
  });
  const response = await handlers.list({ request: request(), env: {} });
  const body = await response.json();
  assert.equal(response.status, 500);
  assert.equal(body.success, false);
  assert.equal(body.error.code, "AGENT_STORE_ERROR");
  assert.doesNotMatch(JSON.stringify(body), /password|postgres/i);
});

test("leaderboard middleware matches only the exact route", async () => {
  const middleware = createLeaderboardMiddleware({
    createStore: () => storeWith([]),
  });
  assert.equal(await middleware({ request: request("/api/agents") }), null);
  assert.equal(await middleware({ request: request("/api/agents/leaderboard/extra") }), null);
  const response = await middleware({ request: request(), env: {} });
  assert.equal(response.status, 200);
});
