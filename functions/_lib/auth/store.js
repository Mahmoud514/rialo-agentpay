import { createD1Store } from "./d1-store.js";
import { createNeonStore } from "./neon-store.js";

// Auth store selection: a Cloudflare D1 binding is the Cloudflare-only path.
// Neon remains the reviewed compatibility path when D1 is absent.
export function createAuthStore(env = {}) {
  if (env.DB) return createD1Store(env.DB);
  return createNeonStore(env);
}
