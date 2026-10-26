#!/usr/bin/env node
// Build the static frontend without requiring Functions or a BACKEND value.
// This is intentionally independent from the Pages Functions deployment: the
// output contains only HTML/CSS/JS assets, so a static preview can be served
// even when the API proxy is not configured.

import { cpSync, existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const source = join(root, "frontend", "src");
const output = join(root, "dist", "static");

if (!existsSync(join(source, "index.html"))) {
  console.error("frontend/src/index.html is missing");
  process.exit(1);
}

rmSync(output, { recursive: true, force: true });
mkdirSync(output, { recursive: true });
cpSync(source, output, {
  recursive: true,
  filter: (path) => !/\.(bak|orig|rej|tmp)$/.test(path),
});

// Keep unknown paths from falling through to the SPA when no Functions are
// deployed. HTML-only fallback is enough for the static preview.
writeFileSync(
  join(output, "404.html"),
  `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Not found — Rialo AgentPay</title><link rel="stylesheet" href="/app.css"></head>
<body><main class="container"><h1>Not found</h1><p>This page is not available in the static preview.</p><p><a href="/">Return home</a></p></main></body></html>
`,
);

console.log(`static build: ${output}`);
