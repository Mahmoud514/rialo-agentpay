import assert from "node:assert/strict";
import { test } from "node:test";

import {
  createTaskReadHandlers,
  createTaskReadMiddleware,
} from "../../functions/_lib/tasks/read-task.js";

function request(path, cookie) {
  const headers = cookie ? { cookie: `agentpay_session=${cookie}` } : {};
  return new Request(`https://app.test${path}`, { method: "GET", headers });
}

function storeFor(task, session = null) {
  return {
    calls: [],
    async getSession() {
      this.calls.push("getSession");
      return session;
    },
    async getTask(id) {
      this.calls.push(`getTask:${id}`);
      return task;
    },
  };
}

test("task list is public for open work and passes the optional viewer id", async () => {
  const seen = [];
  const store = {
    calls: [],
    async getSession() {
      return { user_id: "7", login: "u", expires_at: 2_000 };
    },
    async listTasks(viewerId) {
      seen.push(viewerId);
      return [{ task_id: "t1", status: "open", title: "One" }];
    },
  };
  const handlers = createTaskReadHandlers({ createStore: () => store, now: () => 1000 });
  const response = await handlers.list({ request: request("/api/tasks"), env: {} });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.count, 1);
  assert.deepEqual(seen, [null]);

  const authed = await handlers.list({
    request: request("/api/tasks", "session"),
    env: {},
  });
  assert.equal(authed.status, 200);
  assert.deepEqual(seen, [null, "7"]);
});

test("task list store failure is a typed 503", async () => {
  const handlers = createTaskReadHandlers({
    createStore: () => ({
      async listTasks() {
        throw new Error("postgres password must not leak");
      },
    }),
    now: () => 1000,
  });
  const response = await handlers.list({ request: request("/api/tasks"), env: {} });
  const body = await response.json();
  assert.equal(response.status, 503);
  assert.equal(body.error.code, "TASK_LIST_UNAVAILABLE");
  assert.doesNotMatch(JSON.stringify(body), /password|postgres/i);
});

test("open task detail is public and reads Neon without Blitz", async () => {
  const store = storeFor({ task_id: "t1", status: "open", owner_user_id: "7" });
  const handlers = createTaskReadHandlers({ createStore: () => store, now: () => 1000 });
  const response = await handlers.one({ request: request("/api/tasks/t1"), env: {} }, "t1");
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.task.task_id, "t1");
  assert.equal(body.is_owner, false);
});

test("non-open task detail is hidden from anonymous callers", async () => {
  const store = storeFor({ task_id: "t2", status: "paid", owner_user_id: "7" });
  const handlers = createTaskReadHandlers({ createStore: () => store, now: () => 1000 });
  const response = await handlers.one({ request: request("/api/tasks/t2"), env: {} }, "t2");
  assert.equal(response.status, 404);
  assert.equal((await response.json()).error.code, "TASK_NOT_FOUND");
});

test("authenticated owner sees non-open detail and ownership flags", async () => {
  const store = storeFor(
    { task_id: "t3", status: "paid", owner_user_id: "7", worker_id: "8" },
    { user_id: "7", login: "u", expires_at: 2_000 },
  );
  const handlers = createTaskReadHandlers({ createStore: () => store, now: () => 1000 });
  const response = await handlers.one(
    { request: request("/api/tasks/t3", "session"), env: {} },
    "t3",
  );
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.is_owner, true);
  assert.equal(body.is_worker, false);
});

test("missing task is a 404 and a store failure is a typed 503", async () => {
  const missing = createTaskReadHandlers({
    createStore: () => storeFor(null),
    now: () => 1000,
  });
  assert.equal(
    (await missing.one({ request: request("/api/tasks/none"), env: {} }, "none")).status,
    404,
  );

  const broken = createTaskReadHandlers({
    createStore: () => ({
      async getTask() {
        throw new Error("database password must not leak");
      },
    }),
    now: () => 1000,
  });
  const response = await broken.one(
    { request: request("/api/tasks/t4"), env: {} },
    "t4",
  );
  const body = await response.json();
  assert.equal(response.status, 503);
  assert.equal(body.error.code, "TASK_DETAIL_UNAVAILABLE");
  assert.doesNotMatch(JSON.stringify(body), /password|database/i);
});

test("task middleware ignores open-task and nested routes", async () => {
  const middleware = createTaskReadMiddleware({ createStore: () => storeFor(null) });
  assert.equal(await middleware({ request: request("/api/tasks/open") }), null);
  assert.equal(await middleware({ request: request("/api/tasks/t1/files") }), null);
  const response = await middleware({ request: request("/api/tasks/t1"), env: {} });
  assert.equal(response.status, 404);
});
