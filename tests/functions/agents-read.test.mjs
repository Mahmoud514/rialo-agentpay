import assert from "node:assert/strict";
import { test } from "node:test";

import {
  createAgentReadHandlers,
  createAgentReadMiddleware,
} from "../../functions/_lib/agents/read-agents.js";

const AGENT_ID = "11111111-1111-4111-8111-111111111111";
const FOREIGN_ID = "22222222-2222-4222-8222-222222222222";

function request(path, { cookie = "session-token", method = "GET" } = {}) {
  return new Request(`https://app.example${path}`, {
    method,
    headers: cookie ? { cookie: `agentpay_session=${cookie}` } : {},
  });
}

function store(overrides = {}) {
  return {
    async getSession() {
      return { user_id: "7", login: "owner" };
    },
    async listAgents(userId) {
      assert.equal(userId, "7");
      return [
        {
          schema_version: 1,
          agent_id: AGENT_ID,
          owner_user_id: "7",
          name: "owned",
          status: "active",
          wallet_address: "pub",
          auth_public_key: null,
          created_at: 10,
          updated_at: 11,
        },
      ];
    },
    async getAgent(userId, agentId) {
      assert.equal(userId, "7");
      return agentId === AGENT_ID ? { schema_version: 1, agent_id: AGENT_ID, owner_user_id: "7", name: "owned", status: "active", wallet_address: "pub", auth_public_key: null, created_at: 10, updated_at: 11 } : null;
    },
    ...overrides,
  };
}

function handlers(overrides = {}) {
  const fake = store(overrides);
  return createAgentReadHandlers({
    createStore: () => fake,
    now: () => 1000,
  });
}

test("GET /api/agents returns only the owner's public agent records", async () => {
  const response = await handlers().list({ request: request("/api/agents"), env: {} });
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.success, true);
  assert.equal(body.agents.length, 1);
  assert.equal(body.agents[0].agent_id, AGENT_ID);
  assert.equal(body.agents[0].owner_user_id, 7);
});

test("GET /api/agents/{uuid} hides foreign and missing agents behind 404", async () => {
  const h = handlers();
  const owned = await h.one({ request: request(`/api/agents/${AGENT_ID}`), env: {} }, AGENT_ID);
  assert.equal(owned.status, 200);
  const foreign = await h.one({ request: request(`/api/agents/${FOREIGN_ID}`), env: {} }, FOREIGN_ID);
  assert.equal(foreign.status, 404);
  assert.equal((await foreign.json()).error.code, "AGENT_NOT_FOUND");
  const malformed = await h.one({ request: request("/api/agents/not-a-uuid"), env: {} }, "not-a-uuid");
  assert.equal(malformed.status, 404);
});

test("agent reads require a session and never fall back to Blitz", async () => {
  const response = await handlers().list({ request: request("/api/agents", { cookie: "" }), env: {} });
  assert.equal(response.status, 401);
  assert.equal((await response.json()).error.code, "NOT_AUTHENTICATED");
});

test("agent store failures are typed 500s without leaking database text", async () => {
  const h = handlers({
    async listAgents() {
      throw new Error("DATABASE_URL=postgres://secret@example/db");
    },
  });
  const response = await h.list({ request: request("/api/agents"), env: {} });
  assert.equal(response.status, 500);
  const body = await response.json();
  assert.equal(body.error.code, "AGENT_STORE_ERROR");
  assert.equal(JSON.stringify(body).includes("DATABASE_URL"), false);
  assert.equal(JSON.stringify(body).includes("secret"), false);
});

test("read-only middleware leaves non-owned agent routes to the proxy", async () => {
  const middleware = createAgentReadMiddleware({
    createStore: () => store(),
    now: () => 1000,
  });
  assert.equal(await middleware({ request: request("/api/agents/leaderboard"), env: {} }), null);
  assert.equal(await middleware({ request: request("/api/agents/triggers/payments"), env: {} }), null);
  assert.equal(await middleware({ request: request("/api/tasks/open"), env: {} }), null);
  assert.ok(await middleware({ request: request("/api/agents"), env: {} }));
});
