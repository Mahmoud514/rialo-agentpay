// EVM wallet login primitives.
//
// This module deliberately does not trust any client-supplied "message" or
// "address" value. The caller reconstructs the exact message from the nonce
// row stored in the database, then verifies the signature over that message.

import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { sha256 } from "@noble/hashes/sha256";
import { blake3 } from "@noble/hashes/blake3";
import { bytesToHex, hexToBytes, concatBytes, utf8 } from "./bytes.js";

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const NONCE_RE = /^[A-Za-z0-9_-]{32,128}$/;
const SIGNATURE_RE = /^(?:0x)?[0-9a-fA-F]{130}$/;

export const LOGIN_PURPOSE = "login";
export const LINK_PURPOSE = "link";

export function normalizeEvmAddress(input) {
  const value = String(input ?? "").trim();
  if (!ADDRESS_RE.test(value)) return null;
  return `0x${value.slice(2).toLowerCase()}`;
}

export function isValidNonce(input) {
  return typeof input === "string" && NONCE_RE.test(input);
}

export function newNonce() {
  // 32 random bytes, URL-safe, no padding. This is returned once and only
  // its SHA-256 hash is persisted.
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function nonceHash(nonce) {
  return bytesToHex(sha256(utf8(String(nonce))));
}

export function walletLoginMessage({ origin, address, nonce, issuedAt, expiresAt }) {
  return [
    "Rialo AgentPay",
    `Domain: ${origin}`,
    `Address: ${address}`,
    "Purpose: login",
    `Nonce: ${nonce}`,
    `Issued At: ${issuedAt}`,
    `Expires At: ${expiresAt}`,
  ].join("\n");
}

export function walletLinkMessage({ origin, address, userId, nonce, issuedAt, expiresAt }) {
  return [
    "Rialo AgentPay",
    `Domain: ${origin}`,
    `Address: ${address}`,
    "Purpose: link",
    `Account: ${userId}`,
    `Nonce: ${nonce}`,
    `Issued At: ${issuedAt}`,
    `Expires At: ${expiresAt}`,
  ].join("\n");
}

export function eip191Hash(message) {
  const body = utf8(String(message));
  const prefix = utf8(`\x19Ethereum Signed Message:\n${body.length}`);
  return keccak_256(concatBytes(prefix, body));
}

/**
 * Recover the signer address from a 65-byte EVM personal_sign signature.
 * Returns a lowercase 0x-prefixed address, or null for malformed signatures.
 */
export function recoverEvmAddress(message, signatureHex) {
  const value = String(signatureHex ?? "").trim();
  if (!SIGNATURE_RE.test(value)) return null;
  const signature = hexToBytes(value);
  if (!signature || signature.length !== 65) return null;

  const recoveryByte = signature[64];
  const recovery = recoveryByte >= 27 ? recoveryByte - 27 : recoveryByte;
  if (recovery !== 0 && recovery !== 1) return null;

  try {
    const compact = signature.slice(0, 64);
    const sig = secp256k1.Signature.fromCompact(compact).addRecoveryBit(recovery);
    const publicKey = sig.recoverPublicKey(eip191Hash(message)).toRawBytes(false);
    if (!publicKey || publicKey.length !== 65 || publicKey[0] !== 4) return null;
    const addressBytes = keccak_256(publicKey.slice(1)).slice(-20);
    return `0x${bytesToHex(addressBytes)}`;
  } catch {
    return null;
  }
}

export function verifyWalletSignature({ address, message, signatureHex }) {
  const normalized = normalizeEvmAddress(address);
  if (!normalized) return false;
  const recovered = recoverEvmAddress(message, signatureHex);
  return recovered !== null && recovered === normalized;
}

/**
 * Must remain byte-for-byte compatible with Rust wallet_user_id():
 * first 8 BLAKE3 bytes, big-endian, top two bits cleared, bit 62 set.
 *
 * Returns a decimal string because PostgreSQL BIGINT and JSON do not safely
 * represent every u64 as a JavaScript Number.
 */
export function walletUserId(address) {
  const normalized = normalizeEvmAddress(address);
  if (!normalized) return null;
  const hash = blake3(utf8(normalized));
  let value = 0n;
  for (let i = 0; i < 8; i += 1) {
    value = (value << 8n) | BigInt(hash[i]);
  }
  value &= 0x3fff_ffff_ffff_ffffn;
  value |= 0x4000_0000_0000_0000n;
  return value.toString(10);
}

export function walletLoginFromAddress(address) {
  const normalized = normalizeEvmAddress(address);
  if (!normalized) return null;
  return {
    id: walletUserId(normalized),
    login: normalized,
    name: "Wallet user",
    avatar_url: null,
  };
}
