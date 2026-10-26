#!/usr/bin/env node
// Deployment preflight for Pages Functions.
// Prints only variable NAMES, never values. Exit 1 blocks a Functions deploy.
import { parseBackend } from "../functions/_lib/proxy.js";

export function validateConfig(env = {}) {
  const errors = [];
  const authMode = String(env.AUTH_MODE || "proxy").toLowerCase();
  const tasksMode = String(env.TASKS_MODE || "proxy").toLowerCase();
  const staticOnly = String(env.FUNCTIONS_STATIC_ONLY || "") === "1";

  if (staticOnly) return { ok: true, errors, mode: "static-only" };

  if (!parseBackend(env.BACKEND)) errors.push("BACKEND (valid https origin)");
  if (authMode === "worker" && !env.DATABASE_URL) errors.push("DATABASE_URL (AUTH_MODE=worker)");
  if (tasksMode === "neon" && !env.DATABASE_URL) errors.push("DATABASE_URL (TASKS_MODE=neon)");
  if (env.AUTH_MODE && !["worker", "proxy"].includes(authMode)) {
    errors.push("AUTH_MODE (worker|proxy)");
  }
  if (env.TASKS_MODE && !["neon", "proxy"].includes(tasksMode)) {
    errors.push("TASKS_MODE (neon|proxy)");
  }
  return { ok: errors.length === 0, errors, mode: errors.length === 0 ? authMode : "invalid" };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const result = validateConfig(process.env);
  if (!result.ok) {
    console.error("Functions configuration is incomplete:");
    for (const name of result.errors) console.error(`- ${name}`);
    process.exit(1);
  }
  console.log(`Functions configuration OK (${result.mode}).`);
}
