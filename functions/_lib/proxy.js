// Shared Pages Functions proxy helper.
//
// Cloudflare Pages passes { request, env } to onRequest. Configuration is
// request-scoped: a missing BACKEND must NOT throw at module load, otherwise a
// static preview that includes the functions directory cannot build or serve
// the static site. Backend-dependent routes fail closed with a typed 503.

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
  "content-length",
  "accept-encoding",
]);

const STRIP_RES = new Set([
  "content-length",
  "transfer-encoding",
  "connection",
  "keep-alive",
  "strict-transport-security",
  "access-control-allow-origin",
  "access-control-allow-credentials",
  "access-control-allow-headers",
  "access-control-expose-headers",
  "vary",
]);

/** Validate a configured backend origin. Returns null on any unsafe value. */
export function parseBackend(raw) {
  if (typeof raw !== "string") return null;
  const value = raw.trim();
  if (!value || value.length > 2048) return null;
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return null;
  }
  if (parsed.protocol !== "https:") return null;
  if (parsed.username || parsed.password) return null;
  if (parsed.search || parsed.hash) return null;
  if (parsed.pathname !== "/" && parsed.pathname !== "") return null;
  if (!parsed.hostname || parsed.hostname.includes("%")) return null;
  // Reject explicit malformed ports; URL already validates the numeric range.
  if (parsed.port && !/^\d{1,5}$/.test(parsed.port)) return null;
  return parsed.origin;
}

function jsonError(code, message, status = 503) {
  return new Response(JSON.stringify({ success: false, error: { code, message } }), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

/** Proxy a Pages request to the request-scoped BACKEND, preserving the path. */
export async function proxyRequest(context) {
  const request = context?.request;
  if (!request) return jsonError("PROXY_CONFIG_ERROR", "The proxy request is unavailable.");

  const backend = parseBackend(context?.env?.BACKEND);
  if (!backend) {
    // Do not echo the configuration value. A static-only preview never needs
    // this path; a Functions deployment with a typo fails closed here.
    return jsonError("PROXY_CONFIG_ERROR", "The backend proxy is not configured.");
  }

  const incoming = new URL(request.url);
  const outURL = new URL(backend);
  // Assign pathname/search onto the validated origin. Never use
  // new URL(incoming.pathname, backend): a leading // could escape the host.
  outURL.pathname = incoming.pathname;
  outURL.search = incoming.search;

  const headers = new Headers();
  request.headers.forEach((value, key) => {
    const lower = key.toLowerCase();
    if (STRIP_REQ.has(lower)) return;
    headers.set(key, value);
  });
  ["authorization", "x-api-key"].forEach((h) => headers.delete(h));

  const method = request.method.toUpperCase();
  const upstream = await fetch(outURL, {
    method,
    headers,
    redirect: "manual",
    body: method === "GET" || method === "HEAD" ? undefined : request.body,
  });

  const responseHeaders = new Headers();
  upstream.headers.forEach((value, key) => {
    const lower = key.toLowerCase();
    if (STRIP_RES.has(lower)) return;
    responseHeaders.set(key, value);
  });

  return new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: responseHeaders,
  });
}
