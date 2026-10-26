import assert from "node:assert/strict";
import { test } from "node:test";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";

import { MemoryAuthStore } from "../../functions/_lib/auth/memory-store.js";
import { route, createAuthHandler } from "../../functions/_lib/auth/router.js";
import {
  eip191Hash,
  nonceHash,
  normalizeEvmAddress,
  walletLinkMessage,
  walletLoginMessage,
  walletUserId,
} from "../../functions/_lib/auth/wallet.js";
import {
  SESSION_COOKIE,
  SESSION_TTL_SECONDS,
  sessionHash,
} from "../../functions/_lib/auth/session.js";
import { bytesToHex, utf8 } from "../../functions/_lib/auth/bytes.js";

const ORIGIN = "https://app.example";

function jsonRequestAt(origin, path, body, headers = {}) {
  return new Request(`${origin}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", origin, ...headers },
    body: JSON.stringify(body),
  });
}

function jsonRequest(path, body, headers = {}) {
  return jsonRequestAt(ORIGIN, path, body, headers);
}

function cookieFrom(response) {
  const raw = response.headers.get("set-cookie");
  assert.ok(raw, "expected Set-Cookie");
  const pair = raw.split(";")[0];
  assert.ok(pair.startsWith(`${SESSION_COOKIE}=`));
  return pair.slice(SESSION_COOKIE.length + 1);
}

function addressForPrivateKey(privateKey) {
  const publicKey = secp256k1.getPublicKey(privateKey, false);
  return `0x${bytesToHex(keccak_256(publicKey.slice(1)).slice(-20))}`;
}

function sign(message, privateKey) {
  const signature = secp256k1.sign(eip191Hash(message), privateKey);
  const bytes = new Uint8Array(65);
  bytes.set(signature.toCompactRawBytes());
  bytes[64] = signature.recovery + 27;
  return bytesToHex(bytes);
}

async function getNonce(store, address, clock = 1_000) {
  const response = await route(
    jsonRequest("/auth/wallet/nonce", { address }),
    store,
    { now: () => clock, secure: false },
  );
  const body = await response.json();
  return { response, body };
}

async function login(store, privateKey, clock = 1_000) {
  const address = addressForPrivateKey(privateKey);
  const { response: nonceResponse, body: nonce } = await getNonce(store, address, clock);
  assert.equal(nonceResponse.status, 200);
  const verify = await route(
    jsonRequest("/auth/wallet/verify", {
      address,
      nonce: nonce.nonce,
      signature_hex: sign(nonce.message, privateKey),
    }),
    store,
    { now: () => clock, secure: false },
  );
  const verified = await verify.json();
  return { address, nonce, verify, verified, cookie: cookieFrom(verify) };
}

test("nonce response stores only a hash and binds the exact origin/message", async () => {
  const store = new MemoryAuthStore();
  const address = "0x0000000000000000000000000000000000000001";
  const { response, body } = await getNonce(store, address);

  assert.equal(response.status, 200);
  assert.equal(body.success, true);
  assert.match(body.message, /Domain: https:\/\/app\.example/);
  assert.match(body.message, /Address: 0x0000000000000000000000000000000000000001/);
  assert.ok(store.nonces.has(nonceHash(body.nonce)));
  assert.equal(store.nonces.has(body.nonce), false);
  assert.equal(store.nonces.get(nonceHash(body.nonce)).consumed_at, null);
  assert.equal(store.nonces.get(nonceHash(body.nonce)).message.includes(body.nonce), false);
  assert.match(store.nonces.get(nonceHash(body.nonce)).message, /\{\{nonce\}\}/);
});

test("wallet login enqueues V8 provisioning without waiting for a signer", async () => {
  const store = new MemoryAuthStore();
  const calls = [];
  store.enqueueProvisioning = async (userId, now) => {
    calls.push([String(userId), now]);
    return true;
  };
  const privateKey = secp256k1.utils.randomPrivateKey();
  const result = await login(store, privateKey);
  assert.equal(result.verify.status, 200);
  assert.deepEqual(calls, [[result.verified.user.id, 1_000]]);
});

test("an enqueue failure never changes a successful login", async () => {
  const store = new MemoryAuthStore();
  store.enqueueProvisioning = async () => {
    throw new Error("outbox unavailable");
  };
  const privateKey = secp256k1.utils.randomPrivateKey();
  const result = await login(store, privateKey);
  assert.equal(result.verify.status, 200);
  assert.equal(result.verified.success, true);
  assert.ok(result.cookie);
});

test("wallet login issues a Blitz-compatible session and a hashed lookup row", async () => {
  const store = new MemoryAuthStore();
  const privateKey = secp256k1.utils.randomPrivateKey();
  const result = await login(store, privateKey);

  assert.equal(result.verify.status, 200);
  assert.equal(result.verified.success, true);
  assert.equal(result.verified.user.id, walletUserId(result.address));

  const row = store.sessions.get(result.cookie);
  assert.ok(row, "raw session id must remain available to Blitz");
  assert.equal(row.session_id, result.cookie);
  assert.equal(row.session_hash, sessionHash(result.cookie));
  assert.equal(row.expires_at, 1_000 + SESSION_TTL_SECONDS);
  assert.equal(row.auth_method, "wallet");
  assert.ok(row.csrf_hash);

  const setCookie = result.verify.headers.get("set-cookie");
  assert.match(setCookie, /HttpOnly/);
  assert.match(setCookie, /SameSite=Lax/);
  assert.doesNotMatch(setCookie, /Secure/); // test options use secure:false
});

test("production session cookies are Secure, HttpOnly, SameSite=Lax, and bounded", async () => {
  const store = new MemoryAuthStore();
  const privateKey = secp256k1.utils.randomPrivateKey();
  const address = addressForPrivateKey(privateKey);
  const { body: nonce } = await getNonce(store, address);
  const verify = await route(
    jsonRequest("/auth/wallet/verify", {
      address,
      nonce: nonce.nonce,
      signature_hex: sign(nonce.message, privateKey),
    }),
    store,
    { now: () => 1_000, secure: true },
  );
  const setCookie = verify.headers.get("set-cookie");
  assert.equal(verify.status, 200);
  assert.match(setCookie, /HttpOnly/);
  assert.match(setCookie, /SameSite=Lax/);
  assert.match(setCookie, /Secure/);
  assert.match(setCookie, /Max-Age=604800/);
});

test("a nonce can be consumed exactly once", async () => {
  const store = new MemoryAuthStore();
  const privateKey = secp256k1.utils.randomPrivateKey();
  const address = addressForPrivateKey(privateKey);
  const { body: nonce } = await getNonce(store, address);
  const payload = {
    address,
    nonce: nonce.nonce,
    signature_hex: sign(nonce.message, privateKey),
  };

  const first = await route(jsonRequest("/auth/wallet/verify", payload), store, {
    now: () => 1_000,
    secure: false,
  });
  const second = await route(jsonRequest("/auth/wallet/verify", payload), store, {
    now: () => 1_000,
    secure: false,
  });

  assert.equal(first.status, 200);
  assert.equal(second.status, 400);
  assert.equal((await second.json()).error.code, "WALLET_NONCE_INVALID");
});

test("expired nonces fail closed", async () => {
  const store = new MemoryAuthStore();
  const privateKey = secp256k1.utils.randomPrivateKey();
  const address = addressForPrivateKey(privateKey);
  const { body: nonce } = await getNonce(store, address, 1_000);

  const response = await route(
    jsonRequest("/auth/wallet/verify", {
      address,
      nonce: nonce.nonce,
      signature_hex: sign(nonce.message, privateKey),
    }),
    store,
    { now: () => 1_000 + 301, secure: false },
  );

  assert.equal(response.status, 400);
  assert.equal((await response.json()).error.code, "WALLET_NONCE_INVALID");
});

test("a nonce issued for one origin cannot be verified on another origin", async () => {
  const store = new MemoryAuthStore();
  const privateKey = secp256k1.utils.randomPrivateKey();
  const address = addressForPrivateKey(privateKey);
  const { body: nonce } = await getNonce(store, address);

  const response = await route(
    jsonRequestAt("https://evil.example", "/auth/wallet/verify", {
      address,
      nonce: nonce.nonce,
      signature_hex: sign(nonce.message, privateKey),
    }),
    store,
    { now: () => 1_000, secure: false },
  );

  assert.equal(response.status, 400);
  assert.equal((await response.json()).error.code, "WALLET_NONCE_INVALID");
});

test("a nonce issued for login cannot be used as a link nonce", async () => {
  const store = new MemoryAuthStore();
  const account = await login(store, secp256k1.utils.randomPrivateKey());
  const otherKey = secp256k1.utils.randomPrivateKey();
  const otherAddress = addressForPrivateKey(otherKey);
  const { body: nonce } = await getNonce(store, otherAddress);

  const response = await route(
    jsonRequest(
      "/auth/wallet/link/verify",
      {
        address: otherAddress,
        nonce: nonce.nonce,
        signature_hex: sign(nonce.message, otherKey),
      },
      {
        cookie: `${SESSION_COOKIE}=${account.cookie}`,
        "x-csrf-token": account.verified.csrf_token,
      },
    ),
    store,
    { now: () => 1_000, secure: false },
  );

  assert.equal(response.status, 400);
  assert.equal((await response.json()).error.code, "WALLET_NONCE_INVALID");
});

test("a link nonce is bound to the session user and cannot be replayed cross-user", async () => {
  const store = new MemoryAuthStore();
  const first = await login(store, secp256k1.utils.randomPrivateKey());
  const second = await login(store, secp256k1.utils.randomPrivateKey());
  const linkKey = secp256k1.utils.randomPrivateKey();
  const linkAddress = addressForPrivateKey(linkKey);

  const nonceResponse = await route(
    jsonRequest(
      "/auth/wallet/link/nonce",
      { address: linkAddress },
      {
        cookie: `${SESSION_COOKIE}=${first.cookie}`,
        "x-csrf-token": first.verified.csrf_token,
      },
    ),
    store,
    { now: () => 1_000, secure: false },
  );
  const nonce = await nonceResponse.json();

  const response = await route(
    jsonRequest(
      "/auth/wallet/link/verify",
      {
        address: linkAddress,
        nonce: nonce.nonce,
        signature_hex: sign(nonce.message, linkKey),
      },
      {
        cookie: `${SESSION_COOKIE}=${second.cookie}`,
        "x-csrf-token": second.verified.csrf_token,
      },
    ),
    store,
    { now: () => 1_000, secure: false },
  );

  assert.equal(response.status, 400);
  assert.equal((await response.json()).error.code, "WALLET_NONCE_INVALID");
  assert.equal(store.identities.has(`wallet:${linkAddress}`), false);
});

test("a signature for a different address is rejected", async () => {
  const store = new MemoryAuthStore();
  const privateKey = secp256k1.utils.randomPrivateKey();
  const otherAddress = addressForPrivateKey(secp256k1.utils.randomPrivateKey());
  const { body: nonce } = await getNonce(store, otherAddress);

  const response = await route(
    jsonRequest("/auth/wallet/verify", {
      address: otherAddress,
      nonce: nonce.nonce,
      signature_hex: sign(nonce.message, privateKey),
    }),
    store,
    { now: () => 1_000, secure: false },
  );

  assert.equal(response.status, 401);
  assert.equal((await response.json()).error.code, "WALLET_SIGNATURE_INVALID");
});

test("nonce issuance is rate limited without exposing the raw IP", async () => {
  const store = new MemoryAuthStore();
  const address = "0x0000000000000000000000000000000000000001";
  const statuses = [];
  for (let i = 0; i < 11; i += 1) {
    const { response } = await getNonce(store, address);
    statuses.push(response.status);
  }
  assert.equal(statuses.at(-1), 429);
  assert.equal(statuses.filter((status) => status === 200).length, 10);
  assert.ok(store.calls.some(([method]) => method === "hitRateLimit"));
});

test("the IP bucket prevents address rotation from bypassing rate limits", async () => {
  const store = new MemoryAuthStore();
  const statuses = [];
  for (let i = 0; i < 61; i += 1) {
    const address = `0x${i.toString(16).padStart(40, "0")}`;
    const { response } = await getNonce(store, address);
    statuses.push(response.status);
  }
  assert.equal(statuses.filter((status) => status === 200).length, 60);
  assert.equal(statuses.at(-1), 429);
});

test("wallet linking requires a session, CSRF, and a signed link nonce", async () => {
  const store = new MemoryAuthStore();
  const accountKey = secp256k1.utils.randomPrivateKey();
  const account = await login(store, accountKey);
  const linkKey = secp256k1.utils.randomPrivateKey();
  const linkAddress = addressForPrivateKey(linkKey);

  const nonceWithoutCsrf = await route(
    jsonRequest(
      "/auth/wallet/link/nonce",
      { address: linkAddress },
      { cookie: `${SESSION_COOKIE}=${account.cookie}` },
    ),
    store,
    { now: () => 1_000, secure: false },
  );
  assert.equal(nonceWithoutCsrf.status, 403);
  assert.equal((await nonceWithoutCsrf.json()).error.code, "CSRF_INVALID");

  const nonceResponse = await route(
    jsonRequest(
      "/auth/wallet/link/nonce",
      { address: linkAddress },
      {
        cookie: `${SESSION_COOKIE}=${account.cookie}`,
        "x-csrf-token": account.verified.csrf_token,
      },
    ),
    store,
    { now: () => 1_000, secure: false },
  );
  const nonce = await nonceResponse.json();
  assert.equal(nonceResponse.status, 200);

  const verify = await route(
    jsonRequest(
      "/auth/wallet/link/verify",
      {
        address: linkAddress,
        nonce: nonce.nonce,
        signature_hex: sign(nonce.message, linkKey),
      },
      {
        cookie: `${SESSION_COOKIE}=${account.cookie}`,
        "x-csrf-token": account.verified.csrf_token,
      },
    ),
    store,
    { now: () => 1_000, secure: false },
  );
  const linked = await verify.json();
  assert.equal(verify.status, 200);
  assert.equal(linked.linked, true);
  assert.equal(store.identities.get(`wallet:${linkAddress}`).user_id, account.verified.user.id);
  assert.equal(store.sessions.has(account.cookie), false);
  const rotatedCookie = cookieFrom(verify);
  assert.notEqual(rotatedCookie, account.cookie);
  assert.equal(store.sessions.get(rotatedCookie).auth_method, "wallet_link");
  assert.ok(linked.csrf_token);
  assert.equal(
    nonce.message,
    walletLinkMessage({
      origin: ORIGIN,
      address: linkAddress,
      userId: account.verified.user.id,
      nonce: nonce.nonce,
      issuedAt: 1_000,
      expiresAt: 1_300,
    }),
  );
});

test("a wallet already linked to another account cannot be linked", async () => {
  const store = new MemoryAuthStore();
  const owner = await login(store, secp256k1.utils.randomPrivateKey());
  const otherKey = secp256k1.utils.randomPrivateKey();
  const otherAddress = addressForPrivateKey(otherKey);
  store.identities.set(`wallet:${otherAddress}`, {
    provider: "wallet",
    subject: otherAddress,
    user_id: "999",
    login: "other",
    verified_at: 1,
  });

  const nonceResponse = await route(
    jsonRequest(
      "/auth/wallet/link/nonce",
      { address: otherAddress },
      {
        cookie: `${SESSION_COOKIE}=${owner.cookie}`,
        "x-csrf-token": owner.verified.csrf_token,
      },
    ),
    store,
    { now: () => 1_000, secure: false },
  );
  const nonce = await nonceResponse.json();
  const verify = await route(
    jsonRequest(
      "/auth/wallet/link/verify",
      {
        address: otherAddress,
        nonce: nonce.nonce,
        signature_hex: sign(nonce.message, otherKey),
      },
      {
        cookie: `${SESSION_COOKIE}=${owner.cookie}`,
        "x-csrf-token": owner.verified.csrf_token,
      },
    ),
    store,
    { now: () => 1_000, secure: false },
  );

  assert.equal(verify.status, 409);
  assert.equal((await verify.json()).error.code, "WALLET_ALREADY_LINKED");
});

test("a wallet-only account with activity is never merged automatically", async () => {
  const store = new MemoryAuthStore();
  const github = await login(store, secp256k1.utils.randomPrivateKey());
  const walletKey = secp256k1.utils.randomPrivateKey();
  const walletAddress = addressForPrivateKey(walletKey);
  store.activity.add(walletUserId(walletAddress));

  const nonceResponse = await route(
    jsonRequest(
      "/auth/wallet/link/nonce",
      { address: walletAddress },
      {
        cookie: `${SESSION_COOKIE}=${github.cookie}`,
        "x-csrf-token": github.verified.csrf_token,
      },
    ),
    store,
    { now: () => 1_000, secure: false },
  );
  const nonce = await nonceResponse.json();
  const verify = await route(
    jsonRequest(
      "/auth/wallet/link/verify",
      {
        address: walletAddress,
        nonce: nonce.nonce,
        signature_hex: sign(nonce.message, walletKey),
      },
      {
        cookie: `${SESSION_COOKIE}=${github.cookie}`,
        "x-csrf-token": github.verified.csrf_token,
      },
    ),
    store,
    { now: () => 1_000, secure: false },
  );

  assert.equal(verify.status, 409);
  assert.equal((await verify.json()).error.code, "WALLET_HAS_SEPARATE_ACCOUNT");
});

test("legacy raw-only sessions can bootstrap CSRF without changing their token format", async () => {
  const store = new MemoryAuthStore();
  store.sessions.set("legacy-session", {
    session_id: "legacy-session",
    session_hash: null,
    user_id: "123",
    login: "legacy",
    expires_at: null,
    auth_method: null,
    csrf_hash: null,
  });

  const csrfResponse = await route(
    jsonRequest(
      "/auth/csrf",
      {},
      { cookie: `${SESSION_COOKIE}=legacy-session`, origin: ORIGIN },
    ),
    store,
    { now: () => 1_000, secure: false },
  );
  const csrf = await csrfResponse.json();
  assert.equal(csrfResponse.status, 200);
  assert.ok(csrf.csrf_token);
  assert.equal(store.sessions.get("legacy-session").session_id, "legacy-session");

  const nonceResponse = await route(
    jsonRequest(
      "/auth/wallet/link/nonce",
      { address: "0x0000000000000000000000000000000000000002" },
      {
        cookie: `${SESSION_COOKIE}=legacy-session`,
        origin: ORIGIN,
        "x-csrf-token": csrf.csrf_token,
      },
    ),
    store,
    { now: () => 1_000, secure: false },
  );
  assert.equal(nonceResponse.status, 200);
});

test("legacy raw-only sessions remain readable during the transition", async () => {
  const store = new MemoryAuthStore();
  store.sessions.set("legacy-session", {
    session_id: "legacy-session",
    session_hash: null,
    user_id: "123",
    login: "legacy",
    expires_at: null,
    auth_method: null,
    csrf_hash: null,
  });

  const response = await route(
    jsonRequest(
      "/auth/wallet/link/nonce",
      { address: "0x0000000000000000000000000000000000000002" },
      { cookie: `${SESSION_COOKIE}=legacy-session`, origin: ORIGIN },
    ),
    store,
    { now: () => 1_000, secure: false },
  );

  assert.equal(response.status, 403); // authenticated legacy session, but no CSRF is available
  assert.equal((await response.json()).error.code, "CSRF_INVALID");
});

test("database failures fail closed without leaking secrets or nonce values", async () => {
  const store = new MemoryAuthStore();
  store.createNonce = async () => {
    throw new Error("DATABASE_URL=postgres://secret@example/db");
  };

  const response = await route(
    jsonRequest("/auth/wallet/nonce", {
      address: "0x0000000000000000000000000000000000000001",
    }),
    store,
    { now: () => 1_000, secure: false },
  );
  const text = await response.text();

  assert.equal(response.status, 503);
  assert.match(text, /AUTH_UNAVAILABLE/);
  assert.doesNotMatch(text, /postgres:\/\//i);
  assert.doesNotMatch(text, /secret/i);
});

test("wallet user id matches the Rust blake3 fixture", () => {
  assert.equal(
    walletUserId("0xabc0000000000000000000000000000000000001"),
    "6406668901610920728",
  );
});

test("wallet user id keeps the Rust-compatible top-bit shape", () => {
  const id = BigInt(walletUserId("0x0000000000000000000000000000000000000001"));
  assert.ok((id & 0x4000_0000_0000_0000n) !== 0n);
  assert.equal(id & 0xc000_0000_0000_0000n, 0x4000_0000_0000_0000n);
});

test("a missing database configuration also fails closed", async () => {
  const handler = createAuthHandler({
    createStore: () => {
      throw new Error("missing env");
    },
  });
  const response = await handler({
    request: jsonRequest("/auth/wallet/nonce", {
      address: "0x0000000000000000000000000000000000000001",
    }),
    env: {},
  });
  assert.equal(response.status, 503);
  assert.equal((await response.json()).error.code, "AUTH_UNAVAILABLE");
});

test("normalization rejects malformed addresses", () => {
  assert.equal(normalizeEvmAddress("0xABC0000000000000000000000000000000000001"), "0xabc0000000000000000000000000000000000001");
  assert.equal(normalizeEvmAddress("0x123"), null);
  assert.equal(normalizeEvmAddress("not-an-address"), null);
});
