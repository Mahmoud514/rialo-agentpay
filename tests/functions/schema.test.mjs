import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

import { CREDENTIALS_SCHEMA, handleSchema } from "../../functions/_lib/schema.js";

const source = JSON.parse(
  fs.readFileSync(
    path.resolve(import.meta.dirname, "../../src/schema/credentials.schema.json"),
    "utf8",
  ),
);

test("Worker schema response matches the canonical schema document", async () => {
  assert.deepEqual(CREDENTIALS_SCHEMA, source);
  const response = await handleSchema(new Request("https://app.test/api/schema"));
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-type"), "application/json; charset=utf-8");
  assert.deepEqual(await response.json(), source);
});

test("Worker schema rejects non-GET without a fake success", async () => {
  const response = await handleSchema(
    new Request("https://app.test/api/schema", { method: "POST" }),
  );
  assert.equal(response.status, 405);
  assert.equal((await response.json()).error.code, "METHOD_NOT_ALLOWED");
});
