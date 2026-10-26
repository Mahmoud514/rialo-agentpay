// Worker-owned read-only task board.
//
// This route moves only the public/open listing. Task creation, claiming,
// submission, review, cancel, payouts, and recovery remain on the backend until
// their signer/payment paths are migrated and reviewed.
//
// The response shape matches the existing GET /api/tasks/open contract:
// { tasks: [...], count: number }. It reads Neon only and never calls Blitz.

import { createNeonStore } from "../auth/neon-store.js";
import { readSessionCookie, sessionHash } from "../auth/session.js";

function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...headers,
    },
  });
}

function unavailable() {
  return json(
    { success: false, error: { code: "TASK_LIST_UNAVAILABLE", message: "Task listing temporarily unavailable." } },
    503,
  );
}

export async function handleOpenTasks(request, store, { now = Math.floor(Date.now() / 1000) } = {}) {
  if (request.method !== "GET") {
    return json(
      { success: false, error: { code: "METHOD_NOT_ALLOWED", message: "Use GET." } },
      405,
      { allow: "GET" },
    );
  }

  let viewerId = null;
  const raw = readSessionCookie(request);
  if (raw && store.getSession) {
    const session = await store.getSession({
      tokenHash: sessionHash(raw),
      rawToken: raw,
      now,
    });
    if (session) viewerId = String(session.user_id);
  }

  if (!store.listOpenTasks) return unavailable();
  const tasks = await store.listOpenTasks(viewerId);
  const rows = Array.isArray(tasks) ? tasks : [];
  return json({
    tasks: rows.map((task) => ({
      task_id: String(task.task_id),
      title: String(task.title ?? ""),
      status: String(task.status ?? ""),
      reward_rlo: Number(task.reward_rlo),
      owner_name: String(task.owner_name ?? ""),
      worker_name: String(task.worker_name ?? ""),
      created_at: Number(task.created_at),
    })),
    count: rows.length,
  });
}

export function createOpenTasksHandler({ createStore = createNeonStore, now } = {}) {
  return async function handleOpenTasksRequest(context) {
    let store;
    try {
      store = createStore(context?.env ?? {});
    } catch {
      return unavailable();
    }
    try {
      return await handleOpenTasks(context.request, store, {
        now: typeof now === "function" ? now() : undefined,
      });
    } catch {
      return unavailable();
    }
  };
}

export const handleOpenTasksRequest = createOpenTasksHandler();
