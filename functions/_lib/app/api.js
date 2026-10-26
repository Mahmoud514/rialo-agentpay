// Cloudflare D1 application routes for the preview console.
//
// Scope: agent registry/read + task board lifecycle that can be represented
// without wallet signing. Payment execution, faucet, public proofs/verify and
// GitHub OAuth are deliberately not implemented here and return typed
// unavailable errors; they must never look successful without the signer.
import { createAuthStore } from "../auth/store.js";
import { readSessionCookie, sessionHash } from "../auth/session.js";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const KELVIN = 1_000_000_000;

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
function now() {
  return Math.floor(Date.now() / 1000);
}
function text(value, max = 4000) {
  return String(value ?? "").slice(0, max);
}
function validName(name) {
  const n = String(name ?? "").trim();
  return n.length >= 1 && n.length <= 64 && !/[\u0000-\u001f\u007f]/.test(n);
}
function validReward(value) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 && n <= 1_000_000;
}
function agentJson(row) {
  if (!row) return null;
  return {
    schema_version: Number(row.schema_version ?? 1),
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
function policyJson(policy) {
  const p = policy && typeof policy === "object" ? policy : {};
  return {
    max_payment_per_tx_kelvin:
      p.max_payment_per_tx_kelvin == null ? null : Number(p.max_payment_per_tx_kelvin),
    daily_payment_limit_kelvin:
      p.daily_payment_limit_kelvin == null ? null : Number(p.daily_payment_limit_kelvin),
    allowed_recipients: Array.isArray(p.allowed_recipients) ? p.allowed_recipients : [],
    allowed_actions: Array.isArray(p.allowed_actions) ? p.allowed_actions : [],
  };
}
function taskJson(row) {
  if (!row) return null;
  let files = [];
  try {
    files = JSON.parse(row.attachments_json || "[]");
  } catch {
    files = [];
  }
  return {
    task_id: String(row.task_id),
    owner_user_id: String(row.owner_user_id),
    owner_name: String(row.owner_name || ""),
    agent_id: row.agent_id == null ? null : String(row.agent_id),
    title: String(row.title || ""),
    description: String(row.description || ""),
    acceptance_criteria: String(row.acceptance_criteria || ""),
    reward_kelvin: Number(row.reward_kelvin || 0),
    reward_rlo: Number(row.reward_kelvin || 0) / KELVIN,
    status: String(row.status || ""),
    worker_id: row.worker_id == null ? null : String(row.worker_id),
    worker_name: row.worker_name == null ? null : String(row.worker_name),
    worker_recipient: row.payout_address == null ? null : String(row.payout_address),
    submission_url: row.submission_url == null ? "" : String(row.submission_url),
    submission_notes: row.submission_notes == null ? "" : String(row.submission_notes),
    submission_files: Array.isArray(files) ? files : [],
    review_notes: row.review_notes == null ? "" : String(row.review_notes),
    payment_tx_signature: row.payment_tx_signature == null ? "" : String(row.payment_tx_signature),
    payment_error: row.payment_error == null ? "" : String(row.payment_error),
    created_at: Number(row.created_at || 0),
    updated_at: Number(row.updated_at || 0),
  };
}

async function sessionFor(store, request) {
  const raw = readSessionCookie(request);
  if (!raw) return null;
  try {
    return await store.getSession({ tokenHash: sessionHash(raw), rawToken: raw, now: now() });
  } catch {
    return null;
  }
}

async function body(request) {
  try {
    const value = await request.json();
    return value && typeof value === "object" ? value : null;
  } catch {
    return null;
  }
}

export async function handleAppRequest(context) {
  const request = context?.request;
  if (!request) return null;
  const url = new URL(request.url);
  const path = url.pathname;
  if (!path.startsWith("/api/")) return null;
  const method = request.method;
  const isAppPath =
    path === "/api/agents" ||
    path === "/api/agents/stats" ||
    path === "/api/tasks" ||
    /^\/api\/agents\/[^/]+(\/(balance|status|policy|stats|activity))?$/.test(path) ||
    /^\/api\/tasks\/[^/]+\/(claim|submit|review|cancel)$/.test(path);
  if (!isAppPath) return null;
  // Existing GET read middlewares handle list/detail; this module handles
  // mutations plus the extra read projections.
  if (method === "GET" && (path === "/api/agents" || path === "/api/tasks")) return null;
  if (method === "GET" && /^\/api\/agents\/[0-9a-f-]{36}$/i.test(path)) return null;
  if (method === "GET" && /^\/api\/tasks\/[^/]+$/.test(path)) return null;

  let store;
  try {
    store = createAuthStore(context.env ?? {});
  } catch {
    return error("APP_UNAVAILABLE", "Application storage is temporarily unavailable.", 503);
  }
  const session = await sessionFor(store, request);
  if (!session) return error("NOT_AUTHENTICATED", "Not logged in", 401);

  try {
    if (path === "/api/agents" && method === "POST") {
      const input = await body(request);
      if (!input || !validName(input.name)) {
        return error("INVALID_AGENT_NAME", "Name must be 1–64 characters.", 400);
      }
      if (typeof store.createAgent !== "function") {
        return error("APP_UNAVAILABLE", "Agent creation is not available.", 503);
      }
      const id = crypto.randomUUID();
      const row = await store.createAgent(String(session.user_id), id, String(input.name).trim(), now());
      return json({ success: true, agent: agentJson(row) }, 201);
    }

    let match = path.match(/^\/api\/agents\/([^/]+)$/);
    if (match && UUID_RE.test(decodeURIComponent(match[1]))) {
      const agentId = decodeURIComponent(match[1]);
      if (method === "PATCH") {
        const input = await body(request);
        if (!input || !validName(input.name)) {
          return error("INVALID_AGENT_NAME", "Name must be 1–64 characters.", 400);
        }
        const row = await store.renameAgent(String(session.user_id), agentId, String(input.name).trim(), now());
        if (!row) return error("AGENT_NOT_FOUND", "Agent not found", 404);
        return json({ success: true, agent: agentJson(row) });
      }
      if (method === "DELETE") {
        const deleted = await store.deleteAgent(String(session.user_id), agentId);
        if (!deleted) return error("AGENT_NOT_DELETABLE", "Only a draft agent can be deleted.", 409);
        return json({ success: true });
      }
    }

    match = path.match(/^\/api\/agents\/([^/]+)\/status$/);
    if (match && method === "PATCH") {
      const agentId = decodeURIComponent(match[1]);
      const input = await body(request);
      if (!input || !["active", "paused", "disabled"].includes(String(input.status))) {
        return error("INVALID_AGENT_STATUS", "Unknown agent status.", 400);
      }
      const result = await store.setAgentStatus(String(session.user_id), agentId, String(input.status), now());
      if (result?.notFound) return error("AGENT_NOT_FOUND", "Agent not found", 404);
      if (result?.invalid) return error("INVALID_AGENT_TRANSITION", "That status transition is not allowed.", 409);
      return json({ success: true, agent: agentJson(result.agent) });
    }

    match = path.match(/^\/api\/agents\/([^/]+)\/policy$/);
    if (match) {
      const agentId = decodeURIComponent(match[1]);
      if (method === "GET") {
        const policy = await store.getAgentPolicy(String(session.user_id), agentId);
        if (policy === null) return error("AGENT_NOT_FOUND", "Agent not found", 404);
        return json({ success: true, policy: policyJson(policy) });
      }
      if (method === "PATCH") {
        const input = await body(request);
        if (!input) return error("INVALID_POLICY", "A JSON body is required.", 400);
        const next = policyJson({});
        for (const key of ["max_payment_per_tx_kelvin", "daily_payment_limit_kelvin"]) {
          if (input[key.replace("_kelvin", "_rlo")] != null) {
            const rlo = Number(input[key.replace("_kelvin", "_rlo")]);
            if (!Number.isFinite(rlo) || rlo < 0) return error("INVALID_POLICY", "Limits must be non-negative RLO.", 400);
            next[key] = Math.round(rlo * KELVIN);
          }
        }
        if (Array.isArray(input.allowed_recipients)) {
          next.allowed_recipients = input.allowed_recipients.map((v) => text(v, 64)).filter(Boolean);
        }
        if (Array.isArray(input.allowed_actions)) {
          next.allowed_actions = input.allowed_actions.filter((v) => v === "payment");
        }
        const saved = await store.setAgentPolicy(String(session.user_id), agentId, next, now());
        if (saved === null) return error("AGENT_NOT_FOUND", "Agent not found", 404);
        return json({ success: true, policy: policyJson(saved) });
      }
    }

    match = path.match(/^\/api\/agents\/([^/]+)\/balance$/);
    if (match && method === "GET") {
      const agentId = decodeURIComponent(match[1]);
      const row = await store.getAgent(String(session.user_id), agentId);
      if (!row) return error("AGENT_NOT_FOUND", "Agent not found", 404);
      if (!row.wallet_address) {
        return json({ success: true, balance_status: "no_wallet", balance: null, balance_error: null });
      }
      return json({
        success: true,
        balance_status: "unavailable",
        balance: null,
        balance_error: { code: "RPC_UNAVAILABLE", message: "Chain RPC is not configured." },
      });
    }

    match = path.match(/^\/api\/agents\/([^/]+)\/stats$/);
    if (match && method === "GET") {
      const agentId = decodeURIComponent(match[1]);
      const row = await store.getAgentStats(String(session.user_id), agentId);
      if (!row) return error("AGENT_NOT_FOUND", "Agent not found", 404);
      return json({
        success: true,
        agent_id: String(row.agent_id),
        name: String(row.name || ""),
        status: String(row.status || ""),
        total_intent_count: Number(row.total_intent_count || 0),
        confirmed_payment_count: Number(row.confirmed_payment_count || 0),
        confirmed_payment_volume_kelvin: Number(row.confirmed_payment_volume_kelvin || 0),
      });
    }

    if (path === "/api/agents/stats" && method === "GET") {
      const agents = await store.listAgents(String(session.user_id));
      return json({
        success: true,
        agent_count: agents.length,
        agents: agents.map((a) => ({ agent_id: String(a.agent_id), name: String(a.name), status: String(a.status) })),
      });
    }

    match = path.match(/^\/api\/agents\/([^/]+)\/activity$/);
    if (match && method === "GET") {
      const agentId = decodeURIComponent(match[1]);
      const agent = await store.getAgent(String(session.user_id), agentId);
      if (!agent) return error("AGENT_NOT_FOUND", "Agent not found", 404);
      const limit = Math.min(Number(url.searchParams.get("limit") || 50) || 50, 100);
      const rows = await store.listAgentActivity(String(session.user_id), agentId, limit);
      return json({ success: true, items: rows.map((r) => ({
        agent_id: agentId,
        kind: String(r.kind),
        at: Number(r.at),
        detail: String(r.detail || ""),
      })), next_cursor: null });
    }

    if (path === "/api/tasks" && method === "POST") {
      const input = await body(request);
      if (!input) return error("INVALID_TASK", "A JSON body is required.", 400);
      if (!UUID_RE.test(String(input.agent_id || ""))) return error("INVALID_TASK", "A valid agent_id is required.", 400);
      if (!validName(input.title) || !text(input.description, 20_000) || !text(input.acceptance_criteria, 20_000)) {
        return error("INVALID_TASK", "Title, description, and acceptance criteria are required.", 400);
      }
      if (!validReward(input.reward_rlo)) return error("INVALID_REWARD", "Reward must be greater than 0 RLO.", 400);
      const agent = await store.getAgent(String(session.user_id), String(input.agent_id));
      if (!agent) return error("AGENT_NOT_FOUND", "Agent not found", 404);
      const row = await store.createTask({
        task_id: crypto.randomUUID(),
        owner_user_id: String(session.user_id),
        owner_name: String(session.login || ""),
        agent_id: String(input.agent_id),
        title: String(input.title).trim(),
        description: text(input.description, 20_000),
        acceptance_criteria: text(input.acceptance_criteria, 20_000),
        reward_kelvin: Math.round(Number(input.reward_rlo) * KELVIN),
        created_at: now(),
      });
      return json({ success: true, task: taskJson(row) }, 201);
    }

    match = path.match(/^\/api\/tasks\/([^/]+)\/(claim|submit|review|cancel)$/);
    if (match) {
      const taskId = decodeURIComponent(match[1]);
      const action = match[2];
      if (!UUID_RE.test(taskId)) return error("TASK_NOT_FOUND", "Task not found", 404);
      const input = (await body(request)) || {};
      if (action === "claim") {
        const existing = await store.getTask(taskId);
        if (!existing) return error("TASK_NOT_FOUND", "Task not found", 404);
        if (String(existing.owner_user_id) === String(session.user_id)) {
          return error("TASK_SELF_CLAIM", "The task owner cannot claim their own task.", 409);
        }
        const address = text(input.recipient_address, 64).trim();
        if (!/^[A-Za-z0-9]{32,44}$/.test(address)) {
          return error("INVALID_RECIPIENT", "A 32–44 character RLO recipient address is required.", 400);
        }
        const result = await store.claimTask(taskId, String(session.user_id), String(session.login || ""), address, now());
        if (result?.conflict) return error("TASK_CONFLICT", "Task is no longer open.", 409);
        return json({ success: true, task: taskJson(result.task) });
      }
      if (action === "submit") {
        const attachments = Array.isArray(input.submission_files) ? input.submission_files.slice(0, 5) : [];
        const result = await store.submitTask(
          taskId,
          String(session.user_id),
          text(input.url, 2000),
          text(input.notes, 20_000),
          attachments,
          now(),
        );
        if (result?.conflict) return error("TASK_CONFLICT", "Task is not in a submittable state.", 409);
        return json({ success: true, task: taskJson(result.task) });
      }
      if (action === "cancel") {
        const cancelled = await store.cancelTask(taskId, String(session.user_id), now());
        if (!cancelled) return error("TASK_CONFLICT", "Only an open task you own can be cancelled.", 409);
        return json({ success: true });
      }
      if (action === "review") {
        // Approval is a money-moving operation. Never mark it paid without the
        // authoritative signer; keep the task in its current state.
        const decision = String(input.action || "");
        if (decision === "approve") {
          return error("PAYOUT_UNAVAILABLE", "Payment execution requires the isolated signer.", 503);
        }
        if (decision === "reject" || decision === "request_changes") {
          const result = await store.reviewTask(
            taskId, String(session.user_id), decision, text(input.notes, 20_000), now(),
          );
          if (result?.conflict) return error("TASK_CONFLICT", "Task is not in a reviewable state.", 409);
          return json({ success: true, task: taskJson(result.task) });
        }
        return error("INVALID_REVIEW_ACTION", "Use approve, reject, or request_changes.", 400);
      }
    }

    return null;
  } catch {
    return error("APP_STORE_ERROR", "Application store could not complete the request.", 500);
  }
}
