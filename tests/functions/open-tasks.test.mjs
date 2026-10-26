// Read-only task board contract tests. No network and no Blitz.
import assert from "node:assert/strict";
import { test } from "node:test";

import {
  createOpenTasksHandler,
  handleOpenTasks,
} from "../../functions/_lib/tasks/open-tasks.js";
import { SESSION_COOKIE } from "../../functions/_lib/auth/session.js";

const ORIGIN = "https://app.example";

function request(path = "/api/tasks/open", { method = "GET", cookie } = {}) {
  const headers = {};
  if (cookie) headers.cookie = `${SESSION_COOKIE}=${cookie}`;
  return new Request(`${ORIGIN}${path}`, { method, headers });
}

const rows = [
  {
    task_id: "task-1",
    title: "A public task",
    status: "open",
    reward_rlo: 0.1,
    owner_name: "owner",
    worker_name: "",
    created_at: 123,
  },
];

test("open task board returns the existing shape without Blitz", async () => {
  let fetched = false;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    fetched = true;
    throw new Error("Blitz must not be called");
  };
  try {
    const store = {
      async listOpenTasks(viewerId) {
        assert.equal(viewerId, null);
        return rows;
      },
    };
    const response = await handleOpenTasks(request(), store, { now: 1_000 });
    const body = await response.json();
    assert.equal(response.status, 200);
    assert.equal(body.count, 1);
    assert.equal(body.tasks[0].task_id, "task-1");
    assert.equal(body.tasks[0].reward_rlo, 0.1);
    assert.equal(fetched, false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("a signed-in viewer id is passed to the visibility query", async () => {
  let seenViewer = null;
  const store = {
    async getSession() {
      return { user_id: "42", session_id: "s" };
    },
    async listOpenTasks(viewerId) {
      seenViewer = viewerId;
      return [];
    },
  };
  const response = await handleOpenTasks(request(undefined, { cookie: "session-token" }), store, { now: 1_000 });
  assert.equal(response.status, 200);
  assert.equal(seenViewer, "42");
  assert.deepEqual(await response.json(), { tasks: [], count: 0 });
});

test("non-GET is rejected without touching storage", async () => {
  let called = false;
  const response = await handleOpenTasks(request(undefined, { method: "POST" }), {
    async listOpenTasks() {
      called = true;
      return [];
    },
  });
  assert.equal(response.status, 405);
  assert.equal(response.headers.get("allow"), "GET");
  assert.equal(called, false);
});

test("storage failure is a typed 503 and does not leak an error", async () => {
  const handler = createOpenTasksHandler({
    createStore: () => ({
      async listOpenTasks() {
        throw new Error("DATABASE_URL=postgres://secret@example/db");
      },
    }),
  });
  const response = await handler({ request: request(), env: {} });
  assert.equal(response.status, 503);
  const body = await response.json();
  assert.equal(body.error.code, "TASK_LIST_UNAVAILABLE");
  assert.equal(JSON.stringify(body).includes("secret"), false);
});
