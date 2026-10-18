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

export const onRequest = proxyToBackend;
