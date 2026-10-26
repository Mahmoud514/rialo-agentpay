// Cloudflare Pages Functions — /auth/*.
//
// Wallet auth endpoints are always Worker-owned (no Blitz fallback). GitHub
// OAuth and other auth paths stay proxied to BACKEND. AUTH_MODE=proxy is only a
// rollback for non-wallet legacy routes. Missing BACKEND is a request-time
// typed 503, never a module-load throw.

import { handleAuthRequest, isWorkerAuthPath } from "../_lib/auth/router.js";
import { proxyRequest } from "../_lib/proxy.js";

export const onRequest = async (context) => {
    const request = context?.request;
    if (!request) {
        return new Response(
            JSON.stringify({ success: false, error: { code: "PROXY_CONFIG_ERROR", message: "The request is unavailable." } }),
            { status: 500, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } },
        );
    }
    const path = new URL(request.url).pathname;
    // Wallet auth is deliberately Cloudflare-owned regardless of AUTH_MODE.
    // AUTH_MODE=proxy is a rollback for non-wallet legacy routes only.
    if (isWorkerAuthPath(path)) {
        return handleAuthRequest(context);
    }
    return proxyRequest(context);
};
