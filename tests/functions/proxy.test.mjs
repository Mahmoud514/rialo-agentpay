// Tests for the Pages Functions proxy contract. No network and no BACKEND
// secret is needed; these exercise request-scoped configuration and host
// confinement.
import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { parseBackend, proxyRequest } from "../../functions/_lib/proxy.js";

const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; });

test("parseBackend accepts only an https origin", () => {
  assert.equal(parseBackend("https://api.example"), "https://api.example");
  assert.equal(parseBackend("https://api.example:8443"), "https://api.example:8443");
  assert.equal(parseBackend("http://api.example"), null);
  assert.equal(parseBackend("https://user:pass@api.example"), null);
  assert.equal(parseBackend("https://api.example/path"), null);
  assert.equal(parseBackend("https://api.example?x=1"), null);
  assert.equal(parseBackend("https://api.example#frag"), null);
  assert.equal(parseBackend(""), null);
  assert.equal(parseBackend(undefined), null);
});

test("missing BACKEND is a typed 503, not a module-load throw", async () => {
  const response = await proxyRequest({
    request: new Request("https://app.example/api/me"),
    env: {},
  });
  assert.equal(response.status, 503);
  const body = await response.json();
  assert.equal(body.error.code, "PROXY_CONFIG_ERROR");
  assert.equal(body.error.message.includes("undefined"), false);
});

test("the proxy keeps the configured host when the path starts with //", async () => {
  let seen;
  globalThis.fetch = async (url, init) => {
    seen = { url: String(url), init };
    return new Response("upstream", { status: 201, headers: { "x-upstream": "yes" } });
  };
  const response = await proxyRequest({
    request: new Request("https://app.example//evil.example/api?q=1", {
      method: "POST",
      headers: { "content-type": "application/json", "x-forwarded-for": "1.2.3.4" },
      body: "{}",
    }),
    env: { BACKEND: "https://api.example" },
  });
  assert.equal(seen.url, "https://api.example//evil.example/api?q=1");
  assert.equal(response.status, 201);
  assert.equal(response.headers.get("x-upstream"), "yes");
  assert.equal(seen.init.headers.get("x-forwarded-for"), null);
});

test("the proxy strips browser-supplied forwarding and auth headers", async () => {
  let headers;
  globalThis.fetch = async (_url, init) => {
    headers = init.headers;
    return new Response("ok");
  };
  await proxyRequest({
    request: new Request("https://app.example/api/x", {
      headers: {
        "cf-connecting-ip": "203.0.113.9",
        "x-real-ip": "203.0.113.9",
        authorization: "Bearer nope",
        "x-api-key": "nope",
        cookie: "agentpay_session=ok",
      },
    }),
    env: { BACKEND: "https://api.example" },
  });
  assert.equal(headers.get("cf-connecting-ip"), null);
  assert.equal(headers.get("x-real-ip"), null);
  assert.equal(headers.get("authorization"), null);
  assert.equal(headers.get("x-api-key"), null);
  assert.equal(headers.get("cookie"), "agentpay_session=ok");
});

test("upstream errors are not converted into a fake success", async () => {
  globalThis.fetch = async () => new Response("bad", { status: 502 });
  const response = await proxyRequest({
    request: new Request("https://app.example/api/x"),
    env: { BACKEND: "https://api.example" },
  });
  assert.equal(response.status, 502);
});
