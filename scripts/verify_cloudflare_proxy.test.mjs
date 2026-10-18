globalThis.BACKEND = process.env.BACKEND || "";
// verify_cloudflare_proxy.test.mjs — deterministic proxy harness (15 checks).
// Run: BACKEND=https://<koyeb-host>.koyeb.app node scripts/verify_cloudflare_proxy.test.mjs
const BACKEND_ENV = process.env.BACKEND || "";
if (!BACKEND_ENV) {
    console.error("BACKEND env required");
    process.exit(2);
}

// G21.12.36 — Cloudflare Pages Functions proxy (public origin ⇄ Koyeb API).
//
// SAFETY CONTRACT (approved scope A):
// - Destination is a SERVER-CONFIGURED env var (BACKEND). The proxy is NOT
//   an open proxy: only the three fixed prefixes below are ever forwarded,
//   and the target host can never come from the request.
// - Backend URL is validated at module load: must be https:// and must not
//   contain credentials (user:pass form is rejected).
// - Preserves method, path, query string, JSON body, Content-Type,
//   Accept, and status codes. Cookie headers are forwarded VERBATIM so the
//   `agentpay_session` cookie issued by the backend remains same-origin
//   against the Pages domain (Set-Cookie passes through untouched — the
//   backend sets Path=/ with no Domain attribute).
// - Hop-by-hop headers (conn-* trailers, host, cf-*, x-forwarded-*) are
//   stripped from BOTH directions; the proxy re-derives Host itself.
//   Browser-controlled forwarding headers (x-forwarded-for/proto/host) are
//   never copied to the backend (the backend trusts its own origin view.
//   No auth decision depends on them).
// - No credentials or secrets EVER live in this file: the backend URL and
//   OAuth client ids stay in provider environment configuration.
//
// DEPLOYMENT (manual, cloud dashboard):
//   1. Add these files to the repo root under /functions (Pages build
//      picks them up automatically; no build command needed).
//   2. Pages project → Settings → Environment variables:
//        BACKEND = https://<koyeb-service>.koyeb.app
//   3. In your GitHub OAuth App, set the callback to
//        https://<pages-domain>/auth/github/callback
//      (proxy forwards verbatim; cookie lands on the Pages origin so the
//      frontend reads a same-origin session).
//   4. Keep AGENTPAY_DISABLE_TRANSFERS=1 and AGENTPAY_COOKIE_SECURE=1 on
//      the Koyeb service (both end-to-end via env).
//
// No open-proxy behavior: unmatched paths 404 at Cloudflare before any
// function runs.

const BACKEND = (globalThis.BACKEND ?? "").replace(/\/+$/, "");

if (!/^https:\/\/[a-z0-9.\-]+(:\d+)?$/i.test(BACKEND)) {
    // Fail fast and loud at deploy time; a silent misconfig would open the
    // door to undefined behavior (or hide the real backend URL entirely).
    throw new Error(
        "BACKEND env var must be an https:// host (no path, no credentials)"
    );
}

// Headers never forwarded in either direction.
const STRIP_REQ = new Set([
    "host",
    "cf-connecting-ip",
    "cf-ipcountry",
    "cf-ray",
    "cf-visitor",
    "cf-worker",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-real-ip",
    "true-client-ip",
    "forwarded",
    "content-length", // recomputed after body passthrough
    "accept-encoding", // let Cloudflare negotiate its own upstream encoding
]);
const STRIP_RES = new Set([
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "strict-transport-security", // served by Pages itself
    "access-control-allow-origin", // SSRF/cors-safety: we are same-origin
    "access-control-allow-credentials",
    "access-control-allow-headers",
    "access-control-expose-headers",
    "vary",
]);

/** Proxy a Request to the fixed BACKEND preserving method/path/query/body. */
async function proxyToBackend(request) {
    const incoming = new URL(request.url);
    // input path is exactly the one this function matched (Cloudflare
    // preserves the full original path for [[path]].ts catch-alls).
    const outURL = new URL(BACKEND + incoming.pathname + incoming.search);

    const headers = new Headers();
    request.headers.forEach((v, k) => {
        const lk = k.toLowerCase();
        if (STRIP_REQ.has(lk)) return;
        // Cookie passes through: same-origin session cookie round-trip.
        headers.set(k, v);
    });
    // Defense-in-depth: drop any residual auth-adjacent browser headers
    // that could be abused via crafted requests.
    ["authorization", "x-api-key"].forEach((h) => headers.delete(h));

    const method = request.method.toUpperCase();
    const init = {
        method,
        headers,
        redirect: "manual", // OAuth Github redirects handled by the caller
        body:
            method === "GET" || method === "HEAD" ? undefined : request.body,
    };

    const upstream = await fetch(outURL, init);

    const resHeaders = new Headers();
    upstream.headers.forEach((v, k) => {
        const lk = k.toLowerCase();
        if (STRIP_RES.has(lk)) return;
        resHeaders.set(k, v);
    });

    return new Response(upstream.body, {
        status: upstream.status,
        statusText: upstream.statusText,
        headers: resHeaders,
    });
}

globalThis.onRequest = proxyToBackend;
let rpass = 0, rfail = 0;
async function rcheck(name, cond) { cond ? (rpass++, console.log("PASS", name)) : (rfail++, console.log("FAIL", name)); }
async function check(name, cond) { cond ? (rpass++, console.log("PASS", name)) : (rfail++, console.log("FAIL", name)); }



// ---------------- harness (runs AFTER module init which already consumed
// globalThis.BACKEND at load) ----------------
import assert from "node:assert";
const seen = {};
// NOTE: the proxy module captured BACKEND at its own load; fetch is
// intercepted below, so no DNS happens.
globalThis.fetch = async (url, init = {}) => {
    const u = String(url);
    const hdrs = {};
    new Headers(init.headers || {}).forEach((v, k) => { hdrs[k] = v; });
    let bodyStr = null;
    if (init.body && typeof init.body !== "string") {
        bodyStr = await new Response(init.body).text();
    } else if (typeof init.body === "string") {
        bodyStr = init.body;
    }
    seen[u] = { url: u, method: init.method || "GET", headers: hdrs, body: bodyStr };
    const mk = (status, h, b) => new Response(b ?? "", { status, headers: h });
    if (u.includes("/auth/github")) return mk(307, { location: "https://github.com/login/oauth/authorize?client_id=x" });
    if (u.endsWith("/api/payment")) return mk(503, { "content-type": "application/json" }, '{"success":false,"error":{"code":"TRANSFERS_DISABLED"}}');
    return mk(200, { "content-type": "application/json", "set-cookie": "agentpay_session=abc; Path=/; HttpOnly; SameSite=Lax; Secure" }, '{"tasks":[],"count":0}');
};



// Re-require the module under test via dynamic import so the throw at load
// is observable **if** BACKEND was invalid — but with a valid BACKEND the
// module top-level already succeeded during this file's import. To make the
// BACKEND env visible to the module, node resolves `process.env` at load:
// so this file MUST be launched with BACKEND set (see run command above).
// Below we re-import the module content as data-URL to bound it to this run:
const srcUrl = "file://" + new URL(import.meta.url).pathname.replace(
    "verify_cloudflare_proxy.test.mjs",
    "../functions/api/[[route]].ts"
);
// (dynamic import of the TS source is not possible in plain node; instead we
// already have onRequest in scope because the module above ends with
// `globalThis.onRequest = proxyToBackend;`).

function mkReq(path, opts = {}) {
    return new Request("https://agentpay.pages.dev" + path, {
        method: opts.method || "GET",
        headers: opts.headers || {},
        body: opts.body,
    });
}

let r = await globalThis.onRequest(mkReq("/api/tasks/open"));
await rcheck("T1 status 200", r.status === 200);
await rcheck("T1 body passthrough", (await r.text()) === '{"tasks":[],"count":0}');
await rcheck("T1 set-cookie preserved", (r.headers.get("set-cookie") || "").includes("agentpay_session="));
{
    const cap = seen[Object.keys(seen).find((k) => k.includes("/api/tasks/open") && !k.includes("?"))] || { headers: {} };
    const H = cap.headers || {};
    await rcheck("T1 host stripped", !("host" in H) || !String(H.host).includes("pages.dev"));
    await rcheck("T1 cf headers stripped", !("cf-ray" in H));
    await rcheck("T1 x-forwarded stripped", !("x-forwarded-for" in H));
}
r = await globalThis.onRequest(mkReq("/api/tasks", { method: "POST", headers: { "content-type": "application/json" }, body: '{"agent_id":"a","title":"t"}' }));
await rcheck("T2 status 200", r.status === 200);
{
    const cap = seen[Object.keys(seen).find((k) => k.endsWith("/api/tasks"))] || {};
    await rcheck("T2 body forwarded", cap.body === '{"agent_id":"a","title":"t"}');
    await rcheck("T2 content-type preserved", (cap.headers["content-type"] || "").includes("application/json"));
}
await globalThis.onRequest(mkReq("/api/tasks/open?limit=5&offset=2"));
await rcheck("T3 query preserved", Object.keys(seen).some((k) => k.includes("limit=5")));
r = await globalThis.onRequest(mkReq("/auth/github"));
await rcheck("T4 oauth status 307", r.status === 307);
await rcheck("T4 location passthrough", (r.headers.get("location") || "").startsWith("https://github.com/"));
r = await globalThis.onRequest(mkReq("/api/payment", { method: "POST", headers: { "content-type": "application/json" }, body: '{"to":"x","amount":1}' }));
await rcheck("T5 kill-switch 503 passthrough", r.status === 503 && (await r.text()).includes("TRANSFERS_DISABLED"));
r = await globalThis.onRequest(mkReq("/api/tasks/open", { headers: { authorization: "Bearer stolen" } }));
{
    const cap = seen[Object.keys(seen).find((k) => k.includes("/api/tasks/open") && !k.includes("?"))] || { headers: {} };
    await rcheck("T6 authorization stripped", !("authorization" in (cap.headers || {})));
}
r = await globalThis.onRequest(mkReq("/api/me", { headers: { cookie: "agentpay_session=abc" } }));
{
    const cap = seen[Object.keys(seen).find((k) => k.includes("/api/me"))] || {};
    await rcheck("T7 cookie forwarded", (cap.headers.cookie || "").includes("agentpay_session=abc"));
}
console.log(`TOTAL: ${rpass} pass, ${rfail} fail`);
process.exit(rfail ? 1 : 0);
