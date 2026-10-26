// Randomness and encoding helpers shared by the Worker auth lane.
// Web Crypto is available in Workers and Node >= 20.

export function randomBytes(length) {
  if (!Number.isInteger(length) || length <= 0) {
    throw new Error("randomBytes length must be a positive integer");
  }
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

export function bytesToBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function randomToken(byteLength = 32) {
  return bytesToBase64Url(randomBytes(byteLength));
}

export function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(hex) {
  const clean = String(hex ?? "").replace(/^0x/i, "");
  if (clean.length === 0 || clean.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(clean)) {
    return null;
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function concatBytes(...arrays) {
  const total = arrays.reduce((sum, array) => sum + array.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const array of arrays) {
    out.set(array, offset);
    offset += array.length;
  }
  return out;
}

export function utf8(input) {
  return new TextEncoder().encode(input);
}
