// Explicit unavailable boundaries for operations that require the isolated
// signer, Rialo RPC, GitHub OAuth, or chain proofs. These responses are typed
// and never claim a payment, balance, or proof succeeded.
function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}
function error(code, message, status) {
  return json({ success: false, error: { code, message } }, status);
}

export function handleSystemRequest(context) {
  const request = context?.request;
  if (!request) return null;
  const url = new URL(request.url);
  const path = url.pathname;
  if (request.method === "GET" && path === "/api/health") {
    // The Worker itself is reachable; no RPC URL is configured on this preview.
    return json({
      agentpay: "ok",
      rialo_rpc: "unavailable",
      block_height: null,
      rpc_url: null,
      error: { code: "RPC_UNAVAILABLE", message: "Rialo RPC is not configured on this preview." },
    });
  }
  if (request.method === "GET" && path === "/api/program/status") {
    return json({
      configured: false,
      program_id: null,
      on_chain: { status: "not_configured" },
      manifest: { aligned_with_deployed_bytecode: false },
      deployed_bug_fixed: false,
      path_enabled: false,
    });
  }
  if (path === "/api/faucet") {
    if (request.method !== "POST") return error("METHOD_NOT_ALLOWED", "Use POST.", 405);
    return error("FAUCET_UNAVAILABLE", "The testnet faucet requires the isolated signer.", 503);
  }
  if (path === "/api/payment") {
    if (request.method !== "POST") return error("METHOD_NOT_ALLOWED", "Use POST.", 405);
    return error("PAYMENT_UNAVAILABLE", "Direct payment requires the isolated signer.", 503);
  }
  if (request.method === "GET" && path === "/api/public/verify") {
    return error("VERIFY_UNAVAILABLE", "Public proof verification requires chain RPC.", 503);
  }
  if (request.method === "GET" && /^\/api\/public\/agents\/[^/]+\/proofs$/.test(path)) {
    return error("PROOFS_UNAVAILABLE", "Public proofs require chain RPC.", 503);
  }
  if (request.method === "GET" && /^\/api\/tasks\/[^/]+\/payout\/reconcile$/.test(path)) {
    return error("PAYOUT_UNAVAILABLE", "Payout reconciliation requires the payment service.", 503);
  }
  return null;
}
