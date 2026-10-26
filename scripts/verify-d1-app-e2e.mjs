// Synthetic E2E for the Cloudflare D1 agent/task lifecycle. No real wallet,
// signature, payment, or faucet operation is performed.
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";

const base = (process.argv[2] || "https://rialo-agentpay-preview.pages.dev").replace(/\/$/, "");
const origin = base;
const hex = (b) => Buffer.from(b).toString("hex");
function key() {
  const privateKey = secp256k1.utils.randomPrivateKey();
  const publicKey = secp256k1.getPublicKey(privateKey, false);
  return { privateKey, address: `0x${hex(keccak_256(publicKey.slice(1)).slice(-20))}` };
}
function eip191(message) {
  const body = new TextEncoder().encode(message);
  const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${body.length}`);
  const all = new Uint8Array(prefix.length + body.length);
  all.set(prefix); all.set(body, prefix.length);
  return keccak_256(all);
}
function sign(privateKey, message) {
  const sig = secp256k1.sign(eip191(message), privateKey);
  const out = new Uint8Array(65); out.set(sig.toCompactRawBytes()); out[64] = sig.recovery + 27; return hex(out);
}
async function request(path, { method = "GET", cookie, body } = {}) {
  const res = await fetch(base + path, {
    method,
    headers: {
      origin,
      ...(cookie ? { cookie } : {}),
      ...(body ? { "content-type": "application/json" } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const text = await res.text();
  let data; try { data = JSON.parse(text); } catch { data = text; }
  return { status: res.status, data, headers: res.headers };
}
async function login(k) {
  const nonce = await request("/auth/wallet/nonce", { method: "POST", body: { address: k.address } });
  const verify = await request("/auth/wallet/verify", {
    method: "POST",
    body: { address: k.address, nonce: nonce.data.nonce, signature_hex: sign(k.privateKey, nonce.data.message) },
  });
  return (verify.headers.get("set-cookie") || "").split(";")[0];
}
function check(label, result, statuses) {
  const ok = statuses.includes(result.status);
  console.log(`${ok ? "PASS" : "FAIL"} ${label} -> ${result.status}${result.data?.error?.code ? " " + result.data.error.code : ""}`);
  if (!ok) throw new Error(`${label} failed: ${result.status} ${JSON.stringify(result.data)}`);
}

const owner = key(); const worker = key();
const ownerCookie = await login(owner);
const workerCookie = await login(worker);
const agent = await request("/api/agents", { method: "POST", cookie: ownerCookie, body: { name: "E2E Agent" } });
check("create agent", agent, [201]);
const agentId = agent.data.agent.agent_id;
check("list agents", await request("/api/agents", { cookie: ownerCookie }), [200]);
const lb = await request("/api/agents/leaderboard", { cookie: ownerCookie });
console.log("leaderboard", lb.status, JSON.stringify(lb.data?.agents?.map((a) => ({ name: a.name, status: a.status }))));
if (lb.status !== 200 || lb.data.agents.length < 1) throw new Error("leaderboard missing created agent");
check("rename agent", await request(`/api/agents/${agentId}`, { method: "PATCH", cookie: ownerCookie, body: { name: "E2E Renamed" } }), [200]);
check("activate agent", await request(`/api/agents/${agentId}/status`, { method: "PATCH", cookie: ownerCookie, body: { status: "active" } }), [200]);
check("policy read", await request(`/api/agents/${agentId}/policy`, { cookie: ownerCookie }), [200]);
check("policy write", await request(`/api/agents/${agentId}/policy`, { method: "PATCH", cookie: ownerCookie, body: { max_payment_per_tx_rlo: 1, allowed_actions: ["payment"] } }), [200]);
check("agent stats", await request(`/api/agents/${agentId}/stats`, { cookie: ownerCookie }), [200]);
check("agent activity", await request(`/api/agents/${agentId}/activity`, { cookie: ownerCookie }), [200]);
const task = await request("/api/tasks", { method: "POST", cookie: ownerCookie, body: { agent_id: agentId, title: "E2E Task", description: "synthetic", acceptance_criteria: "pass", reward_rlo: 0.1 } });
check("create task", task, [201]);
const taskId = task.data.task.task_id;
const task2 = await request("/api/tasks", { method: "POST", cookie: ownerCookie, body: { agent_id: agentId, title: "E2E Cancelled", description: "synthetic", acceptance_criteria: "pass", reward_rlo: 0.1 } });
check("create cancellable task", task2, [201]);
check("cancel task", await request(`/api/tasks/${task2.data.task.task_id}/cancel`, { method: "POST", cookie: ownerCookie, body: {} }), [200]);
check("open tasks", await request("/api/tasks/open"), [200]);
check("task detail owner", await request(`/api/tasks/${taskId}`, { cookie: ownerCookie }), [200]);
check("claim task", await request(`/api/tasks/${taskId}/claim`, { method: "POST", cookie: workerCookie, body: { recipient_address: "A".repeat(32) } }), [200]);
check("submit task", await request(`/api/tasks/${taskId}/submit`, { method: "POST", cookie: workerCookie, body: { notes: "done" } }), [200]);
check("approve blocked", await request(`/api/tasks/${taskId}/review`, { method: "POST", cookie: ownerCookie, body: { action: "approve" } }), [503]);
check("reject allowed", await request(`/api/tasks/${taskId}/review`, { method: "POST", cookie: ownerCookie, body: { action: "reject", notes: "synthetic reject" } }), [200]);
console.log("E2E OK");
