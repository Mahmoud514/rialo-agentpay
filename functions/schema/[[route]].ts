// Cloudflare Pages Functions — /schema/* (backend-dependent proxy).
// Missing BACKEND fails closed per request; it never blocks static assets.

import { proxyRequest } from "../_lib/proxy.js";

export const onRequest = (context) => proxyRequest(context);
