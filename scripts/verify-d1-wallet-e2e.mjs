// G1156 Cloudflare-only wallet-auth verification.
//
// Uses a fresh synthetic EVM key (never a real wallet) to prove the full
// nonce -> EIP-191 signature -> Worker session -> /api/me path. Point BASE_URL
// at a local Wrangler server or a Cloudflare Pages preview with the D1 binding.
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";

const base = (process.argv[2] || "http://127.0.0.1:8800").replace(/\/$/, "");
const origin = base;
const privateKey = secp256k1.utils.randomPrivateKey();
const publicKey = secp256k1.getPublicKey(privateKey, false);
const hex = (b) => Buffer.from(b).toString("hex");
const address = `0x${hex(keccak_256(publicKey.slice(1)).slice(-20))}`;

function eip191(message) {
  const body = new TextEncoder().encode(message);
  const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${body.length}`);
  const all = new Uint8Array(prefix.length + body.length);
  all.set(prefix);
  all.set(body, prefix.length);
  return keccak_256(all);
}

function signature(message) {
  const sig = secp256k1.sign(eip191(message), privateKey);
  const out = new Uint8Array(65);
  out.set(sig.toCompactRawBytes());
  out[64] = sig.recovery + 27;
  return hex(out);
}

async function call(path, init = {}) {
  const res = await fetch(base + path, {
    ...init,
    headers: { origin, ...(init.headers || {}) },
  });
  const text = await res.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = text;
  }
  return { res, body };
}

const nonce = await call("/auth/wallet/nonce", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ address }),
});
if (nonce.res.status !== 200) {
  throw new Error(`nonce ${nonce.res.status} ${JSON.stringify(nonce.body)}`);
}

const verify = await call("/auth/wallet/verify", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    address,
    nonce: nonce.body.nonce,
    signature_hex: signature(nonce.body.message),
  }),
});
if (verify.res.status !== 200) {
  throw new Error(`verify ${verify.res.status} ${JSON.stringify(verify.body)}`);
}

const setCookie = verify.res.headers.get("set-cookie");
if (!setCookie) throw new Error("missing session cookie");
const cookie = setCookie.split(";")[0];
const me = await call("/api/me", { headers: { cookie } });
if (me.res.status !== 200 || me.body.logged_in !== true || me.body.user?.login !== address) {
  throw new Error(`me ${me.res.status} ${JSON.stringify(me.body)}`);
}

console.log(
  JSON.stringify(
    {
      base,
      nonce_status: nonce.res.status,
      verify_status: verify.res.status,
      me_status: me.res.status,
      logged_in: me.body.logged_in,
      wallet_matches: me.body.user?.login === address,
      wallet_status: me.body.wallet_status ?? null,
    },
    null,
    2,
  ),
);
