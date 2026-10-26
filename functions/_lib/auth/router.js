// Worker auth router.
//
// This module is deliberately framework-free so it can run inside a Pages
// Function and be exercised by unit tests without a network or a database.

import { createAuthStore } from "./store.js";
import {
  LINK_PURPOSE,
  LOGIN_PURPOSE,
  isValidNonce,
  newNonce,
  nonceHash,
  normalizeEvmAddress,
  verifyWalletSignature,
  walletLinkMessage,
  walletLoginFromAddress,
  walletLoginMessage,
  walletUserId,
} from "./wallet.js";
import {
  CSRF_HEADER,
  SESSION_TTL_SECONDS,
  clearSessionCookie,
  csrfHash,
  getRequestOrigin,
  ipHash,
  newCsrfToken,
  newSessionId,
  readSessionCookie,
  sessionCookie,
  sessionHash,
  timingSafeHexEqual,
} from "./session.js";

const MAX_BODY_BYTES = 16 * 1024;
const NONCE_TTL_SECONDS = 5 * 60;
const RATE_WINDOW_SECONDS = 60;
const NONCE_RATE_LIMIT = 10;
const VERIFY_RATE_LIMIT = 20;
const IP_RATE_LIMIT = 60;

export const WORKER_AUTH_PATHS = new Set([
  "/auth/wallet/nonce",
  "/auth/wallet/verify",
  "/auth/wallet/link/nonce",
  "/auth/wallet/link/verify",
  "/auth/csrf",
  "/auth/logout",
]);

export function isWorkerAuthPath(pathname) {
  return WORKER_AUTH_PATHS.has(pathname);
}

function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...headers,
    },
  });
}

function apiError(code, message, status = 400, headers = {}) {
  return json({ success: false, error: { code, message } }, status, headers);
}

async function readJson(request) {
  const length = Number(request.headers.get("content-length") ?? "0");
  if (Number.isFinite(length) && length > MAX_BODY_BYTES) return null;
  let text;
  try {
    text = await request.text();
  } catch {
    return null;
  }
  if (text.length > MAX_BODY_BYTES) return null;
  try {
    const value = JSON.parse(text);
    return value && typeof value === "object" && !Array.isArray(value) ? value : null;
  } catch {
    return null;
  }
}

function originAllowed(request, expectedOrigin) {
  const origin = request.headers.get("origin");
  if (!origin) return false;
  return origin === expectedOrigin;
}

async function rateLimited(store, request, route, subject, limit, now) {
  const windowStart = Math.floor(now / RATE_WINDOW_SECONDS) * RATE_WINDOW_SECONDS;
  const ipKey = `ip:${ipHash(request)}`;
  const ip = await store.hitRateLimit(ipKey, windowStart, IP_RATE_LIMIT);
  if (ip.limited) return true;
  const key = `${route}:${ipHash(request)}:${subject ?? "-"}`;
  const result = await store.hitRateLimit(key, windowStart, limit);
  return Boolean(result?.limited);
}

async function sessionFromRequest(store, request, now) {
  const raw = readSessionCookie(request);
  if (!raw) return null;
  return store.getSession({
    tokenHash: sessionHash(raw),
    rawToken: raw,
    now,
  });
}

async function csrfValid(request, session) {
  if (!session?.csrf_hash) return false;
  const header = request.headers.get(CSRF_HEADER);
  if (!header) return false;
  return timingSafeHexEqual(csrfHash(header), session.csrf_hash);
}

async function issueSession(store, user, now, { secure, authMethod = "wallet" }) {
  const sessionId = newSessionId();
  const csrfToken = newCsrfToken();
  await store.createSession({
    session_id: sessionId,
    session_hash: sessionHash(sessionId),
    user_id: user.id,
    login: user.login,
    created_at: now,
    expires_at: now + SESSION_TTL_SECONDS,
    auth_method: authMethod,
    csrf_hash: csrfHash(csrfToken),
  });
  return {
    cookie: sessionCookie(sessionId, { secure, maxAge: SESSION_TTL_SECONDS }),
    csrfToken,
  };
}

async function enqueueProvisioningBestEffort(store, userId, now) {
  // The outbox insert is idempotent and must never make login fail or wait
  // for a signer. Older environments without V8 simply ignore it.
  if (typeof store.enqueueProvisioning !== "function") return;
  try {
    await store.enqueueProvisioning(userId, now);
  } catch {
    // Authentication remains available; /api/me surfaces the absent state.
  }
}

async function resolveWalletUser(store, address, now) {
  const existing = await store.findIdentity("wallet", address);
  if (existing) {
    return {
      id: String(existing.user_id),
      login: existing.login || address,
      name: existing.name || "Wallet user",
      avatar_url: null,
    };
  }

  const synthetic = walletLoginFromAddress(address);
  if (!synthetic) return null;
  const inserted = await store.insertIdentity({
    provider: "wallet",
    subject: address,
    user_id: synthetic.id,
    login: synthetic.login,
    verified_at: now,
  });
  if (inserted) return synthetic;

  // Lost a race with another login for the same address: use the winner.
  const winner = await store.findIdentity("wallet", address);
  if (!winner) return null;
  return {
    id: String(winner.user_id),
    login: winner.login || address,
    name: winner.name || "Wallet user",
    avatar_url: null,
  };
}

async function handleNonce(request, store, { now, secure }) {
  if (!originAllowed(request, getRequestOrigin(request))) {
    return apiError("ORIGIN_REJECTED", "This request origin is not allowed.", 403);
  }
  const body = await readJson(request);
  if (!body) return apiError("INVALID_REQUEST", "A JSON body is required.", 400);
  const address = normalizeEvmAddress(body.address);
  if (!address) {
    return apiError("WALLET_ADDRESS_INVALID", "A 0x-prefixed EVM wallet address is required.", 400);
  }
  if (await rateLimited(store, request, "wallet-nonce", address, NONCE_RATE_LIMIT, now)) {
    return apiError("RATE_LIMITED", "Too many wallet login attempts. Try again shortly.", 429);
  }

  const nonce = newNonce();
  const issuedAt = now;
  const expiresAt = now + NONCE_TTL_SECONDS;
  const origin = getRequestOrigin(request);
  const message = walletLoginMessage({ origin, address, nonce, issuedAt, expiresAt });
  const messageTemplate = walletLoginMessage({
    origin,
    address,
    nonce: "{{nonce}}",
    issuedAt,
    expiresAt,
  });

  await store.createNonce({
    nonce_hash: nonceHash(nonce),
    address,
    purpose: LOGIN_PURPOSE,
    user_id: null,
    message: messageTemplate,
    domain: origin,
    chain_id: null,
    issued_at: issuedAt,
    expires_at: expiresAt,
  });

  return json({
    success: true,
    nonce,
    message,
    expires_at: expiresAt,
  });
}

async function handleVerify(request, store, { now, secure }) {
  // The stored nonce is already bound to the request origin; reject a missing
  // or cross-origin request before consuming it. Keep the nonce-invalid code
  // so no oracle reveals whether a valid nonce exists for another origin.
  if (!originAllowed(request, getRequestOrigin(request))) {
    return apiError("WALLET_NONCE_INVALID", "Invalid or expired wallet login nonce.", 400);
  }
  const body = await readJson(request);
  if (!body) return apiError("INVALID_REQUEST", "A JSON body is required.", 400);
  const address = normalizeEvmAddress(body.address);
  if (!address) {
    return apiError("WALLET_ADDRESS_INVALID", "A 0x-prefixed EVM wallet address is required.", 400);
  }
  if (!isValidNonce(body.nonce)) {
    return apiError("WALLET_NONCE_INVALID", "A valid login nonce is required.", 400);
  }
  if (await rateLimited(store, request, "wallet-verify", address, VERIFY_RATE_LIMIT, now)) {
    return apiError("RATE_LIMITED", "Too many wallet verification attempts. Try again shortly.", 429);
  }

  const row = await store.consumeNonce(nonceHash(body.nonce), now);
  if (
    !row ||
    row.purpose !== LOGIN_PURPOSE ||
    row.address !== address ||
    row.domain !== getRequestOrigin(request)
  ) {
    return apiError("WALLET_NONCE_INVALID", "Invalid or expired wallet login nonce.", 400);
  }
  const message = String(row.message).replace("{{nonce}}", body.nonce);
  if (!verifyWalletSignature({
    address,
    message,
    signatureHex: body.signature_hex,
  })) {
    return apiError("WALLET_SIGNATURE_INVALID", "The wallet signature does not verify for this address and nonce.", 401);
  }

  const user = await resolveWalletUser(store, address, now);
  if (!user) return apiError("AUTH_UNAVAILABLE", "Could not resolve the wallet identity.", 503);

  const issued = await issueSession(store, user, now, { secure });
  await enqueueProvisioningBestEffort(store, user.id, now);
  return json(
    { success: true, user, csrf_token: issued.csrfToken },
    200,
    { "set-cookie": issued.cookie },
  );
}

async function handleLinkNonce(request, store, { now, secure }) {
  if (!originAllowed(request, getRequestOrigin(request))) {
    return apiError("ORIGIN_REJECTED", "This request origin is not allowed.", 403);
  }
  const session = await sessionFromRequest(store, request, now);
  if (!session) return apiError("AUTH_REQUIRED", "Sign in before linking a wallet.", 401);
  if (!(await csrfValid(request, session))) {
    return apiError("CSRF_INVALID", "A valid CSRF token is required.", 403);
  }

  const body = await readJson(request);
  if (!body) return apiError("INVALID_REQUEST", "A JSON body is required.", 400);
  const address = normalizeEvmAddress(body.address);
  if (!address) {
    return apiError("WALLET_ADDRESS_INVALID", "A 0x-prefixed EVM wallet address is required.", 400);
  }
  if (await rateLimited(store, request, "wallet-link-nonce", address, NONCE_RATE_LIMIT, now)) {
    return apiError("RATE_LIMITED", "Too many wallet link attempts. Try again shortly.", 429);
  }

  const nonce = newNonce();
  const issuedAt = now;
  const expiresAt = now + NONCE_TTL_SECONDS;
  const origin = getRequestOrigin(request);
  const userId = String(session.user_id);
  const message = walletLinkMessage({
    origin,
    address,
    userId,
    nonce,
    issuedAt,
    expiresAt,
  });
  const messageTemplate = walletLinkMessage({
    origin,
    address,
    userId,
    nonce: "{{nonce}}",
    issuedAt,
    expiresAt,
  });

  await store.createNonce({
    nonce_hash: nonceHash(nonce),
    address,
    purpose: LINK_PURPOSE,
    user_id: userId,
    message: messageTemplate,
    domain: origin,
    chain_id: null,
    issued_at: issuedAt,
    expires_at: expiresAt,
  });

  return json({ success: true, nonce, message, expires_at: expiresAt });
}

async function handleLinkVerify(request, store, { now, secure }) {
  if (!originAllowed(request, getRequestOrigin(request))) {
    return apiError("ORIGIN_REJECTED", "This request origin is not allowed.", 403);
  }
  const session = await sessionFromRequest(store, request, now);
  if (!session) return apiError("AUTH_REQUIRED", "Sign in before linking a wallet.", 401);
  if (!(await csrfValid(request, session))) {
    return apiError("CSRF_INVALID", "A valid CSRF token is required.", 403);
  }

  const body = await readJson(request);
  if (!body) return apiError("INVALID_REQUEST", "A JSON body is required.", 400);
  const address = normalizeEvmAddress(body.address);
  if (!address) {
    return apiError("WALLET_ADDRESS_INVALID", "A 0x-prefixed EVM wallet address is required.", 400);
  }
  if (!isValidNonce(body.nonce)) {
    return apiError("WALLET_NONCE_INVALID", "A valid link nonce is required.", 400);
  }
  if (await rateLimited(store, request, "wallet-link-verify", address, VERIFY_RATE_LIMIT, now)) {
    return apiError("RATE_LIMITED", "Too many wallet link verification attempts. Try again shortly.", 429);
  }

  const row = await store.consumeNonce(nonceHash(body.nonce), now);
  if (
    !row ||
    row.purpose !== LINK_PURPOSE ||
    row.address !== address ||
    row.domain !== getRequestOrigin(request) ||
    String(row.user_id) !== String(session.user_id)
  ) {
    return apiError("WALLET_NONCE_INVALID", "Invalid or expired wallet link nonce.", 400);
  }
  const message = String(row.message).replace("{{nonce}}", body.nonce);
  if (!verifyWalletSignature({
    address,
    message,
    signatureHex: body.signature_hex,
  })) {
    return apiError("WALLET_SIGNATURE_INVALID", "The wallet signature does not verify for this address and account.", 401);
  }

  const existing = await store.findIdentity("wallet", address);
  if (existing && String(existing.user_id) !== String(session.user_id)) {
    return apiError("WALLET_ALREADY_LINKED", "This wallet is already linked to another account.", 409);
  }
  if (existing) {
    return json({ success: true, linked: true, user_id: String(existing.user_id) });
  }

  // Never silently absorb a wallet-only account that already has data.
  const syntheticId = walletUserId(address);
  if (String(syntheticId) !== String(session.user_id) && await store.hasUserActivity(syntheticId)) {
    return apiError(
      "WALLET_HAS_SEPARATE_ACCOUNT",
      "This wallet already has a separate account and cannot be linked automatically.",
      409,
    );
  }

  const linked = await store.insertIdentity({
    provider: "wallet",
    subject: address,
    user_id: String(session.user_id),
    login: session.login || address,
    verified_at: now,
  });
  if (!linked) {
    const winner = await store.findIdentity("wallet", address);
    if (winner && String(winner.user_id) !== String(session.user_id)) {
      return apiError("WALLET_ALREADY_LINKED", "This wallet is already linked to another account.", 409);
    }
  }

  // A successful new link changes the security context. Rotate the session
  // so the pre-link cookie cannot be reused, and return the new CSRF token.
  if (linked) {
    const issued = await issueSession(
      store,
      { id: String(session.user_id), login: session.login || address },
      now,
      { secure, authMethod: "wallet_link" },
    );
    await store.deleteSession(session.session_id);
    await enqueueProvisioningBestEffort(store, session.user_id, now);
    return json(
      { success: true, linked: true, user_id: String(session.user_id), csrf_token: issued.csrfToken },
      200,
      { "set-cookie": issued.cookie },
    );
  }

  return json({ success: true, linked: true, user_id: String(session.user_id) });
}

async function handleCsrf(request, store, { now, secure }) {
  if (!originAllowed(request, getRequestOrigin(request))) {
    return apiError("ORIGIN_REJECTED", "This request origin is not allowed.", 403);
  }
  const session = await sessionFromRequest(store, request, now);
  if (!session) return apiError("AUTH_REQUIRED", "Sign in before requesting a CSRF token.", 401);

  const csrfToken = newCsrfToken();
  await store.setSessionCsrf(session.session_id, csrfHash(csrfToken));
  return json({ success: true, csrf_token: csrfToken });
}

async function handleLogout(request, store, { now, secure }) {
  if (!originAllowed(request, getRequestOrigin(request))) {
    return apiError("ORIGIN_REJECTED", "This request origin is not allowed.", 403);
  }
  const session = await sessionFromRequest(store, request, now);
  if (session) {
    await store.deleteSession(session.session_id);
  }
  return json({ success: true }, 200, { "set-cookie": clearSessionCookie({ secure }) });
}

export async function route(request, store, options = {}) {
  const now = typeof options.now === "function" ? options.now() : Math.floor(Date.now() / 1000);
  const secure = options.secure !== false;
  const path = new URL(request.url).pathname;
  const method = request.method.toUpperCase();

  try {
    if (path === "/auth/wallet/nonce" && method === "POST") {
      return await handleNonce(request, store, { now, secure });
    }
    if (path === "/auth/wallet/verify" && method === "POST") {
      return await handleVerify(request, store, { now, secure });
    }
    if (path === "/auth/wallet/link/nonce" && method === "POST") {
      return await handleLinkNonce(request, store, { now, secure });
    }
    if (path === "/auth/wallet/link/verify" && method === "POST") {
      return await handleLinkVerify(request, store, { now, secure });
    }
    if (path === "/auth/csrf" && method === "POST") {
      return await handleCsrf(request, store, { now, secure });
    }
    if (path === "/auth/logout" && method === "POST") {
      return await handleLogout(request, store, { now, secure });
    }
    return apiError("NOT_FOUND", "Unknown auth route.", 404);
  } catch {
    // Never log secrets, signatures, nonces, cookies, or database errors here.
    return apiError("AUTH_UNAVAILABLE", "Authentication is temporarily unavailable.", 503);
  }
}

export function createAuthHandler({ createStore = createAuthStore, now, secure } = {}) {
  return async function handleAuthRequest(context) {
    let store;
    try {
      store = createStore(context?.env ?? {});
    } catch {
      return apiError("AUTH_UNAVAILABLE", "Authentication is temporarily unavailable.", 503);
    }
    return route(context.request, store, { now, secure });
  };
}

export const handleAuthRequest = createAuthHandler();
