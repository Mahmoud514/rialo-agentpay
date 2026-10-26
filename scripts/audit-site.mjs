// Read-only site/API audit against a Cloudflare preview. Creates a synthetic
// wallet session, then probes representative GET routes. No secrets are logged.
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";

const base = (process.argv[2] || "https://rialo-agentpay-preview.pages.dev").replace(/\/$/, "");
const origin = base;
const privateKey = secp256k1.utils.randomPrivateKey();
const publicKey = secp256k1.getPublicKey(privateKey, false);
const hex = (b) => Buffer.from(b).toString("hex");
const address = `0x${hex(keccak_256(publicKey.slice(1)).slice(-20))}`;
function eip191(message) {
  const body = new TextEncoder().encode(message);
  const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${body.length}`);
  const all = new Uint8Array(prefix.length + body.length);
  all.set(prefix); all.set(body, prefix.length);
  return keccak_256(all);
}
function signature(message) {
  const sig = secp256k1.sign(eip191(message), privateKey);
  const out = new Uint8Array(65); out.set(sig.toCompactRawBytes()); out[64] = sig.recovery + 27; return hex(out);
}
async function raw(path, init = {}) {
  return fetch(base + path, { ...init, headers: { origin, ...(init.headers || {}) } });
}
const nonceRes = await raw("/auth/wallet/nonce", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ address }) });
const nonce = await nonceRes.json();
const verifyRes = await raw("/auth/wallet/verify", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ address, nonce: nonce.nonce, signature_hex: signature(nonce.message) }) });
const verify = await verifyRes.json();
const cookie = (verifyRes.headers.get("set-cookie") || "").split(";")[0];
console.log("auth", nonceRes.status, verifyRes.status, cookie ? "cookie=yes" : "cookie=no");

const paths = [
  "/", "/wallet", "/wallet.html", "/marketplace", "/marketplace.html",
  "/dashboard", "/agents", "/activity", "/leaderboard", "/verify",
  "/api/me", "/api/schema", "/api/health", "/api/program/status",
  "/api/agents", "/api/agents/leaderboard", "/api/agents/stats",
  "/api/agents/00000000-0000-0000-0000-000000000000/stats",
  "/api/agents/00000000-0000-0000-0000-000000000000/balance",
  "/api/agents/00000000-0000-0000-0000-000000000000/activity",
  "/api/tasks", "/api/tasks/open",
  "/api/tasks/00000000-0000-0000-0000-000000000000",
  "/api/public/verify", "/api/public/agents/00000000-0000-0000-0000-000000000000/proofs",
];
for (const path of paths) {
  const res = await raw(path, { headers: cookie ? { cookie } : {} });
  let code = "";
  try { const body = await res.json(); code = body?.error?.code || (body?.success === false ? "success:false" : ""); } catch {}
  console.log(`${String(res.status).padEnd(3)} ${path}${code ? ` ${code}` : ""}`);
}
