// Worker-owned GET /api/tasks/{id}.
//
// Visibility matches the backend: open tasks are public; any other task is
// visible only to an authenticated caller. The row is read from Neon and is
// never synthesized. The response keeps the backend envelope so the existing
// frontend can consume it without a proxy.
import { createAuthStore } from "../auth/store.js";
import { readSessionCookie, sessionHash } from "../auth/session.js";

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

export function createTaskReadHandlers({
  createStore = createAuthStore,
  now = () => Math.floor(Date.now() / 1000),
} = {}) {
  async function optionalSession(store, request) {
    const raw = readSessionCookie(request);
    if (!raw) return null;
    try {
      return await store.getSession({
        tokenHash: sessionHash(raw),
        rawToken: raw,
        now: now(),
      });
    } catch {
      return null;
    }
  }

  async function list(context) {
    let store;
    try {
      store = createStore(context.env ?? {});
    } catch {
      return error("TASK_LIST_UNAVAILABLE", "Task listing is temporarily unavailable.", 503);
    }
    let session = null;
    try {
      session = await optionalSession(store, context.request);
    } catch {
      session = null;
    }
    let tasks;
    try {
      tasks = await store.listTasks(session ? String(session.user_id) : null);
    } catch {
      return error("TASK_LIST_UNAVAILABLE", "Task listing is temporarily unavailable.", 503);
    }
    return json({ tasks, count: tasks.length });
  }

  async function one(context, taskId) {
    if (!taskId || taskId.includes("/") || taskId === "open") {
      return error("TASK_NOT_FOUND", "Task not found", 404);
    }
    const request = context.request;
    // Avoid a global request hack: resolve the session explicitly below.
    let store;
    try {
      store = createStore(context.env ?? {});
    } catch {
      return error("TASK_DETAIL_UNAVAILABLE", "Task detail is temporarily unavailable.", 503);
    }
    let session = null;
    try {
      session = await optionalSession(store, request);
    } catch {
      session = null;
    }
    let doc;
    try {
      doc = await store.getTask(taskId);
    } catch {
      return error("TASK_DETAIL_UNAVAILABLE", "Task detail is temporarily unavailable.", 503);
    }
    if (!doc) return error("TASK_NOT_FOUND", "Task not found", 404);
    const status = String(doc.status ?? "");
    if (status !== "open" && !session) {
      return error("TASK_NOT_FOUND", "Task not found", 404);
    }
    const userId = session ? String(session.user_id) : null;
    const isOwner = userId !== null && String(doc.owner_user_id) === userId;
    const isWorker = userId !== null && String(doc.worker_id) === userId;
    return json({
      task: doc,
      reservation_status: "n/a (pg-restored)",
      is_owner: isOwner,
      is_worker: isWorker,
    });
  }

  return { list, one };
}

export function createTaskReadMiddleware(options = {}) {
  const handlers = createTaskReadHandlers(options);
  return async function taskRead(context) {
    const request = context?.request;
    if (!request || request.method !== "GET") return null;
    const path = new URL(request.url).pathname;
    if (path === "/api/tasks") return handlers.list(context);
    const match = path.match(/^\/api\/tasks\/([^/]+)$/);
    if (!match || match[1] === "open") return null;
    return handlers.one(context, decodeURIComponent(match[1]));
  };
}
