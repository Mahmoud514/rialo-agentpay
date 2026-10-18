# Cloudflare proxy verification (G21.12.36 A)

Deterministic harness for the `functions/**` proxy routes.

Run:

```
BACKEND=https://<koyeb-host>.koyeb.app node scripts/verify_cloudflare_proxy.test.mjs
```

The harness intercepts `fetch` (no network, no DNS) and asserts 15 behaviors:
status/body passthrough, `set-cookie` preservation, host & `cf-*` /
`x-forwarded-*` / `authorization` stripping, kill-switch 503
`TRANSFERS_DISABLED` passthrough, OAuth 307 location passthrough.
