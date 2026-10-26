// Worker-owned GET /api/agents/leaderboard.
//
// Owner-scoped, read-only projection over the same Neon tables the backend
// uses. It never calls Blitz and never invents a row: a query failure is a
// typed 500 AGENT_STORE_ERROR, never a partial board.
import { createNeonStore } from "../auth/neon-store.js";
import { readSessionCookie, sessionHash } from "../auth/session.js";

const ORDER =
  "confirmed_payment_volume_kelvin DESC, last_confirmed_at DESC, confirmed_payment_count DESC, agent_id ASC";

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

function numberOrZero(value) {
  const n = Number(value ?? 0);
  return Number.isFinite(n) ? n : 0;
}

function rowJson(row) {
  const kelvin = numberOrZero(row.confirmed_payment_volume_kelvin);
  return {
    agent_id: String(row.agent_id),
    name: String(row.name ?? ""),
    status: String(row.status ?? ""),
    total_intent_count: numberOrZero(row.total_intent_count),
    confirmed_payment_count: numberOrZero(row.confirmed_payment_count),
    confirmed_payment_volume_kelvin: kelvin,
    confirmed_payment_volume_rlo: kelvin / 1_000_000_000,
    last_confirmed_at:
      row.last_confirmed_at === null || row.last_confirmed_at === undefined
        ? null
        : Number(row.last_confirmed_at),
    pending_count: numberOrZero(row.pending_count),
    failed_count: numberOrZero(row.failed_count),
    unknown_count: numberOrZero(row.unknown_count),
    reconciled_count: numberOrZero(row.reconciled_count),
  };
}

export function createLeaderboardHandlers({
  createStore = createNeonStore,
  now = () => Math.floor(Date.now() / 1000),
} = {}) {
  async function list(context) {
    const request = context.request;
    const raw = readSessionCookie(request);
    if (!raw) return error("NOT_AUTHENTICATED", "Not logged in", 401);
    let store;
    try {
      store = createStore(context.env ?? {});
    } catch {
      return error("AGENT_STORE_ERROR", "Leaderboard could not be read completely", 500);
    }
    let session;
    try {
      session = await store.getSession({
        tokenHash: sessionHash(raw),
        rawToken: raw,
        now: now(),
      });
    } catch {
      return error("AGENT_STORE_ERROR", "Leaderboard could not be read completely", 500);
    }
    if (!session) return error("NOT_AUTHENTICATED", "Not logged in", 401);
    let rows;
    try {
      rows = await store.getLeaderboard(String(session.user_id));
    } catch {
      return error("AGENT_STORE_ERROR", "Leaderboard could not be read completely", 500);
    }
    const agents = Array.isArray(rows) ? rows.map(rowJson) : [];
    return json({ success: true, agents, total: agents.length, order: ORDER });
  }

  return { list };
}

export function createLeaderboardMiddleware(options = {}) {
  const handlers = createLeaderboardHandlers(options);
  return async function leaderboard(context) {
    const request = context?.request;
    if (!request || request.method !== "GET") return null;
    if (new URL(request.url).pathname !== "/api/agents/leaderboard") return null;
    return handlers.list(context);
  };
}
