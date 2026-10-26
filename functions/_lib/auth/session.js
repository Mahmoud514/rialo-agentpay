// Session and CSRF helpers for the transitional Worker auth lane.

import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, randomToken, utf8 } from "./bytes.js";

export const SESSION_COOKIE = "agentpay_session";
export const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
export const CSRF_HEADER = "x-csrf-token";

export function newSessionId() {
  // 32 random bytes, URL-safe. This remains the value Blitz reads while the
  // compatibility lane is active.
  return randomToken(32);
}

export function sessionHash(sessionId) {
  return bytesToHex(sha256(utf8(String(sessionId))));
}

export function newCsrfToken() {
  return randomToken(32);
}

export function csrfHash(token) {
  return bytesToHex(sha256(utf8(String(token))));
}

export function timingSafeHexEqual(left, right) {
  const a = String(left ?? "");
  const b = String(right ?? "");
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export function sessionCookie(sessionId, { secure = true, maxAge = SESSION_TTL_SECONDS } = {}) {
  const parts = [
    `${SESSION_COOKIE}=${sessionId}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${Math.max(0, Math.floor(maxAge))}`,
  ];
  if (secure) parts.push("Secure");
  return parts.join("; ");
}

export function clearSessionCookie({ secure = true } = {}) {
  return sessionCookie("", { secure, maxAge: 0 });
}

export function parseCookies(cookieHeader) {
  const out = Object.create(null);
  for (const part of String(cookieHeader ?? "").split(";")) {
    const index = part.indexOf("=");
    if (index <= 0) continue;
    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (!name) continue;
    try {
      out[name] = decodeURIComponent(value);
    } catch {
      out[name] = value;
    }
  }
  return out;
}

export function readSessionCookie(request) {
  return parseCookies(request.headers.get("cookie"))[SESSION_COOKIE] ?? null;
}

export function getRequestOrigin(request) {
  const url = new URL(request.url);
  return url.origin;
}

export function getClientIp(request) {
  // Cloudflare overwrites cf-connecting-ip at the edge. Never trust
  // X-Forwarded-For/X-Real-IP from the client: they are user-controlled.
  const cloudflareIp = request.headers.get("cf-connecting-ip");
  return cloudflareIp ? cloudflareIp.trim() : "unknown";
}

export function ipHash(request) {
  return bytesToHex(sha256(utf8(getClientIp(request))));
}
