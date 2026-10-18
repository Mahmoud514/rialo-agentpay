# Production Deployment Template (PROPOSAL — grounded in current source behavior)
Status: PLANNING ONLY. Nothing here has been deployed or executed. Requires a
real host, domain, TLS certificate, and PostgreSQL instance supplied by the
operator. All placeholders in `<ANGLE_BRACKETS>` must be filled by the operator.

## 1. Preconditions the operator must supply
- A Linux host reachable over the internet with ports 80/443 open for the proxy.
- A domain name + TLS certificate (Let's Encrypt/acme or corporate CA).
- A PostgreSQL 15+ instance and connection URL (`DATABASE_URL`) — never reuse a
  test/embedded database.
- An isolated testnet wallet funded with the probe amount only (0.001 RLO).
- The `rialo` CLI binary matching the configured RPC protocol.
- A private git remote + CI (see MIGRATION.md) so `Cargo.lock` audits run.

## 2. Build & release artifact
```bash
cd /home/mahmoud/rialo-agentpay
cargo +nightly build --release --features server --bin server
# binary: target/release/server   (ship with the exact commit hash recorded)
```
Signing/running: do NOT run as root; dedicated service user `agentpay` with a
private home holding wallet/auth-key material (0600, dir 0700).

## 3. Environment (secrets injected via the service manager, never .env in repo)
Required at startup (names only — values operator-supplied):
- `SERVER_ADDR=127.0.0.1:8080` (app stays loopback; proxy is public)
- `DATABASE_URL=<operator-provided postgres url>`
- `RIALO_RPC_URL=<testnet RPC URL>` / `RIALO_CLI_PATH=<path>`
- `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` / `GITHUB_REDIRECT_URI=https://<domain>/auth/github/callback`
- `AGENTPAY_COOKIE_SECURE=1`            (REQUIRED for HTTPS)
- `AGENTPAY_ISOLATED_SIGNER_LANE` / `AGENTPAY_ISOLATED_SIGNER_URL=http://127.0.0.1:9000`
- `DEV_LOGIN_USER_ID` — **MUST BE UNSET** (route removal + fail-closed warning verified;
  startup log must not show the dev-login warning)
- `AGENTPAY_SIGNER_ADMIN_SECRET` etc. — operator-provided, never in repo

## 4. systemd units (template — requires operator authorization to install)
`/etc/systemd/system/agentpay.service`:
```ini
[Unit]
Description=Rialo AgentPay server
After=network-online.target postgresql.service
[Service]
User=agentpay
WorkingDirectory=/opt/agentpay
EnvironmentFile=/etc/agentpay/env    # 0600 root:agentpay
ExecStart=/opt/agentpay/server
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/agentpay/artifact
PrivateTmp=true
[Install]
WantedBy=multi-user.target
```
Signer: keep the existing loopback :9000 service; verify `ss -ltn` shows it
bound to 127.0.0.1 only — never 0.0.0.0.

## 5. Reverse proxy (TLS termination) — nginx template
```nginx
server {
  listen 443 ssl http2;
  server_name <DOMAIN>;
  ssl_certificate     /etc/letsencrypt/live/<DOMAIN>/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/<DOMAIN>/privkey.pem;
  location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    client_max_body_size 2m;
  }
}
server { listen 80; server_name <DOMAIN>; return 301 https://$host$request_uri; }
```

## 6. Deployment verification checklist (run after each release)
1. `curl -I https://<DOMAIN>/api/health` → 200; `Set-Cookie` (when present) contains
   `HttpOnly`, `SameSite=Lax`, `Secure`.
2. `curl -I http://<DOMAIN>/api/health` → 301 → https.
3. `/auth/dev-login` → 404.
4. `curl -s https://<DOMAIN>/api/health` → NO `rpc_url`, NO upstream error text.
5. Login over the browser: cookie has `Secure; HttpOnly; SameSite=Lax`.
6. `ss -ltn` on host: 8080 and 9000 NOT bound to 0.0.0.0.
7. Recovery sweep POST with operator session → 200, body `"errors":[]`.
8. Weekly security-audit workflow green.
9. Backup job (TODO section 8c.7 of runbook) produced an archive AND a restore
   drill passed in the scratch environment.

## 7. Failure handling
- On 5xx/UNKNOWN outcomes: follow runbook Section 5 (abort/snapshot/pause-agent);
  never hand-edit state; the recovery engine is the only sanctioned writer.
- Alert rules (proposed): → any payment/reconcile route 5xx; → any sweep with
  non-empty `errors`; → any UNKNOWN intent older than the stale window; → backup
  job failure → page the operator.
