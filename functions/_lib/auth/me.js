// Worker-owned GET /api/me.
//
// This exists so a wallet session remains observable when Blitz is stopped.
// It reads Neon only: session, user_wallets pubkey, no RPC and no signer call.
// It never returns private key material.

import { createAuthStore } from "./store.js";
import { sessionHash, readSessionCookie } from "./session.js";

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function emptyResponse() {
  return json({
    logged_in: false,
    user: null,
    wallet_address: null,
    balance: null,
    balance_status: "no_wallet",
    balance_error: null,
    wallet_status: "no_wallet",
  });
}

export async function handleMe(request, store, { now = Math.floor(Date.now() / 1000) } = {}) {
  const raw = readSessionCookie(request);
  if (!raw) return emptyResponse();

  const session = await store.getSession({
    tokenHash: sessionHash(raw),
    rawToken: raw,
    now,
  });
  if (!session) return emptyResponse();

  const wallet = store.getUserWallet
    ? await store.getUserWallet(String(session.user_id))
    : null;

  let provisioning = null;
  try {
    provisioning = store.getProvisioning
      ? await store.getProvisioning(String(session.user_id))
      : null;
  } catch {
    // Provisioning status is advisory; a failure must not invalidate the
    // session or cause a fake "ready" state.
    provisioning = null;
  }

  const provisioningState = provisioning?.state ?? null;
  const walletStatus = wallet
    ? "ready"
    : provisioningState === "pending" || provisioningState === "provisioning"
      ? "provisioning"
      : "no_wallet";

  return json({
    logged_in: true,
    user: {
      id: String(session.user_id),
      login: session.login,
      name: null,
      avatar_url: null,
    },
    wallet_address: wallet?.pubkey ?? null,
    balance: null,
    // Balance is an RPC/Blitz responsibility; this endpoint must not pretend
    // it is zero or call the stopped backend.
    balance_status: wallet ? "unavailable" : "no_wallet",
    balance_error: null,
    wallet_status: walletStatus,
    provisioning,
  });
}

export function createMeHandler({ createStore = createAuthStore, now } = {}) {
  return async function handleMeRequest(context) {
    // A logged-out request must not require a database binding. Without this
    // check, a static/preview deployment with AUTH_MODE=worker but no Neon
    // configuration returns 503 for a harmless GET /api/me.
    if (!readSessionCookie(context?.request)) return emptyResponse();
    let store;
    try {
      store = createStore(context?.env ?? {});
    } catch {
      return json(
        { success: false, error: { code: "AUTH_UNAVAILABLE", message: "Authentication is temporarily unavailable." } },
        503,
      );
    }
    try {
      return await handleMe(context.request, store, {
        now: typeof now === "function" ? now() : undefined,
      });
    } catch {
      return json(
        { success: false, error: { code: "AUTH_UNAVAILABLE", message: "Authentication is temporarily unavailable." } },
        503,
      );
    }
  };
}

export const handleMeRequest = createMeHandler();
