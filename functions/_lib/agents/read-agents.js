// Worker-owned read-only agent routes.
//
// GET /api/agents and GET /api/agents/{uuid} are owner-scoped reads. They use
// Neon only and never call Blitz. Missing and foreign records collapse to the
// same 404, matching the backend's non-enumerating contract. Mutating agent
// routes remain proxied.

import { createAuthStore } from "../auth/store.js";
import { readSessionCookie, sessionHash } from "../auth/session.js";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function error(code, message, status) {
  return json({ success: false, error: { code, message } }, status);
}

function normalizeAgent(row) {
  if (!row) return null;
  return {
    schema_version: Number(row.schema_version),
    agent_id: String(row.agent_id),
    owner_user_id: Number(row.owner_user_id),
    name: String(row.name),
    status: String(row.status),
    wallet_address: row.wallet_address == null ? null : String(row.wallet_address),
    auth_public_key: row.auth_public_key == null ? null : String(row.auth_public_key),
    created_at: Number(row.created_at),
    updated_at: Number(row.updated_at),
  };
}

async function getSessionUser(store, request, now) {
  const raw = readSessionCookie(request);
  if (!raw) return null;
  return store.getSession({
    tokenHash: sessionHash(raw),
    rawToken: raw,
    now,
  });
}

export function createAgentReadHandlers({ createStore = createAuthStore, now } = {}) {
  function clock() {
    return typeof now === "function" ? now() : Math.floor(Date.now() / 1000);
  }

  async function withStore(context, fn) {
    let store;
    try {
      store = createStore(context?.env ?? {});
    } catch {
      return error("AUTH_UNAVAILABLE", "Authentication is temporarily unavailable.", 503);
    }
    try {
      return await fn(store);
    } catch {
      return error("AGENT_STORE_ERROR", "Agent store could not be read", 500);
    }
  }

  async function list(context) {
    if (!readSessionCookie(context.request)) {
      return error("NOT_AUTHENTICATED", "Not logged in", 401);
    }
    return withStore(context, async (store) => {
      const session = await getSessionUser(store, context.request, clock());
      if (!session) {
        return error("NOT_AUTHENTICATED", "Not logged in", 401);
      }
      if (typeof store.listAgents !== "function") {
        return error("AGENT_STORE_ERROR", "Agent store could not be read", 500);
      }
      const rows = await store.listAgents(String(session.user_id));
      return json({ success: true, agents: rows.map(normalizeAgent) });
    });
  }

  async function one(context, agentId) {
    if (!readSessionCookie(context.request)) {
      return error("NOT_AUTHENTICATED", "Not logged in", 401);
    }
    if (!UUID_RE.test(agentId)) {
      return error("AGENT_NOT_FOUND", "Agent not found", 404);
    }
    return withStore(context, async (store) => {
      const session = await getSessionUser(store, context.request, clock());
      if (!session) {
        return error("NOT_AUTHENTICATED", "Not logged in", 401);
      }
      if (typeof store.getAgent !== "function") {
        return error("AGENT_STORE_ERROR", "Agent store could not be read", 500);
      }
      const row = await store.getAgent(String(session.user_id), agentId);
      if (!row) return error("AGENT_NOT_FOUND", "Agent not found", 404);
      return json({ success: true, agent: normalizeAgent(row) });
    });
  }

  return { list, one };
}

export function createAgentReadMiddleware(options = {}) {
  const handlers = createAgentReadHandlers(options);
  return async function handleAgentRead(context) {
    const path = new URL(context.request.url).pathname;
    if (path === "/api/agents") return handlers.list(context);
    const match = path.match(
      /^\/api\/agents\/([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/i,
    );
    if (match) return handlers.one(context, match[1]);
    return null;
  };
}
