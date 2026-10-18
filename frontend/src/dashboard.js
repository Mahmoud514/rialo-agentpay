/*
 * Dashboard page: live control-center read-outs.
 *
 * Data sources — GET ONLY (no POST/PUT ever fires from this page):
 *   GET /api/me             via AgentPayAuth.fetchMe() (auth.js)
 *   GET /api/health         network probe (agentpay, rpc, block height)
 *   GET /api/program/status program readiness snapshot (read-only)
 *
 * Auth: AgentPayAuth owns the navbar chip and body.is-authed exactly like
 * wallet.js — do not duplicate session logic here.
 *
 * Scope note: Wallet balance, faucet, and direct payments are owned by the
 * dedicated /wallet.html page — the dashboard no longer renders them.
 *
 * Honesty rules (Phase 4 audit, still in force):
 *   - payment history has NO data source — static dashed empty state in
 *     dashboard.html, never filled with fabricated numbers;
 *   - the Agents card is a pure entry point to /agents.html (Phase 5 Step 9
 *     dashboard) — this page fires no agent API calls and renders no agent
 *     data itself;
 *   - an unavailable network state never renders as a fake value;
 *   - nothing here reads or displays wallet key files or server paths.
 */

const githubLogin = document.querySelector(".github-login");

const $ = (id) => document.getElementById(id);

function setStatus(el, kind, label) {
    if (!el) return;
    el.className = "status " + kind;
    const text = el.querySelector(".status__label");
    if (text) text.textContent = label;
}

function setKv(id, value, tone) {
    const el = $(id);
    if (!el) return;
    el.textContent = value;
    el.className = tone || "neutral";
    if (el.classList.contains("dash-id")) el.classList.add("dash-id");
}

/* primary metric figure (Network block height): lime when live, muted
   is-na treatment when the RPC probe fails — never a stale/fake number */
function setMetric(id, value, live) {
    const el = $(id);
    if (!el) return;
    el.textContent = value;
    el.classList.toggle("is-na", !live);
}

async function getJson(url) {
    try {
        const response = await fetch(url, {
            method: "GET",
            credentials: "same-origin",
            cache: "no-store",
        });
        return await response.json().catch(() => null);
    } catch (error) {
        console.error(`Failed to load ${url}:`, error);
        return null;
    }
}

// ---------------------------------------------------------------------------
// PAGE HEAD STATUS STRIP  (GET /api/health)
// ---------------------------------------------------------------------------
function renderHealth(health) {
    const ok = Boolean(health) && health.agentpay === "ok";

    setStatus($("statusAgentpay"), ok ? "status--on" : "status--warn",
        ok ? "AgentPay Operational" : "AgentPay — error response");

    setKv("netAgentpay", ok ? "ok" : (health ? String(health.agentpay) : "unreachable"),
        ok ? "ok" : "bad");

    if (health && health.rialo_rpc === "ok") {
        setStatus($("statusRpc"), "status--on", "Rialo RPC Online");
        setStatus($("netPrimaryState"), "status--on", "Live");
        setKv("netRpc", "online", "ok");
        const height = Number(health.block_height);
        const heightText = Number.isFinite(height) ? height.toLocaleString("en-US") : "—";
        $("blockHeight").textContent = heightText;
        setMetric("netHeight", heightText, true);
        setKv("netRpcUrl", health.rpc_url || "—", "neutral");
    } else {
        setStatus($("statusRpc"), "status--off", "Rialo RPC Unavailable");
        setStatus($("netPrimaryState"), "status--off", "Unavailable");
        setKv("netRpc", health ? `unavailable — ${health.error?.code || "error"}` : "unreachable", "bad");
        $("blockHeight").textContent = "—";
        setMetric("netHeight", "—", false);
        setKv("netRpcUrl", health?.rpc_url || "—", "neutral");
    }
}

// ---------------------------------------------------------------------------
// PROGRAM CARD  (GET /api/program/status)
// ---------------------------------------------------------------------------
function renderProgram(snapshot) {
    if (!snapshot || snapshot.configured !== true) {
        setStatus($("programState"), "status--off", "Not Configured");
        setKv("progId", snapshot && snapshot.program_id ? snapshot.program_id : "—", "neutral");
        setKv("progOnchain", "—", "neutral");
        setKv("progManifest", "—", "neutral");
        setKv("progBug", "—", "neutral");
        setKv("progPath", "unavailable", "bad");
        setKv("progRoute", "direct /api/payment", "neutral");
        return;
    }

    const onchain = snapshot.on_chain?.status || "unknown";
    const aligned = snapshot.manifest?.aligned_with_deployed_bytecode === true;

    setStatus($("programState"),
        onchain === "deployed" ? "status--on" : "status--warn",
        onchain === "deployed" ? "Deployed On-Chain" : `On-chain: ${onchain}`);

    setKv("progId", snapshot.program_id, "ok");
    setKv("progOnchain", onchain, onchain === "deployed" ? "ok" : "warn");
    setKv("progManifest",
        aligned ? "aligned with deployed bytecode" : "validation failed",
        aligned ? "ok" : "bad");
    setKv("progBug",
        snapshot.deployed_bug_fixed === true ? "fixed (verified on Testnet)" : "unresolved",
        snapshot.deployed_bug_fixed === true ? "ok" : "bad");

    if (snapshot.path_enabled === true) {
        setKv("progPath", "enabled by operator cap", "ok");
    } else {
        // The honest default: deployed but safety-capped OFF. Never present
        // the program path as a usable payment lane.
        setKv("progPath", "safety-capped — disabled", "warn");
    }

    setKv("progRoute", "direct (/api/payment) — via Wallet page", "neutral");
}

// ---------------------------------------------------------------------------
// ACCOUNT CARD  (GET /api/me)
// The dedicated Wallet page owns balance, faucet, and payment UI — the
// dashboard's Account card shows identity (avatar/name/@login/CONNECTED),
// the public wallet address with copy, and an Open Wallet action. Wallet
// address is a public value; no key material or file paths ever render.
// ---------------------------------------------------------------------------
function renderLoggedOut() {
    setStatus($("accountState"), "status--na", "Not Signed In");

    const body = $("accountBody");
    if (body) {
        body.innerHTML = `
            <div class="gated-note">
                <span class="badge">Auth&nbsp;required</span>
                <span>Sign in with GitHub to view your account and wallet.</span>
                <a class="wallet-btn wallet-btn--solid" href="/auth/github">
                    Login&nbsp;with&nbsp;GitHub
                    <span>↗</span>
                </a>
            </div>`;
    }
}

function renderAccount(data) {
    const user = data.user;
    const name = user.name || user.login || "GitHub User";
    const login = user.login ? `@${user.login}` : "";
    const address = data.wallet_address || "";

    setStatus($("accountState"), "status--on", "Signed In");

    const esc = AgentPayAuth.escapeHtml;
    const avatarMarkup = user.avatar_url
        ? `<img class="github-avatar" src="${esc(user.avatar_url)}" alt="${esc(name)}" data-initial="${esc(name)}">`
        : `<span class="github-avatar github-avatar--fallback" aria-hidden="true">${esc((name || "U").charAt(0).toUpperCase())}</span>`;

    const body = $("accountBody");
    if (body) {
        body.innerHTML = `
            <div class="dash-user">
                ${avatarMarkup}
                <span class="dash-user-info">
                    <strong>${esc(name)}</strong>
                    <span>${esc(login)}</span>
                </span>
                <span class="connected-badge">CONNECTED</span>
            </div>
            ${address ? `
            <div>
                <small class="field-label">Wallet&nbsp;Address</small>
                <div class="dash-wallet-row">
                    <span class="dash-wallet-address" id="dashWalletAddress">${esc(address)}</span>
                    <button type="button" class="wallet-btn copy-btn" id="copyDashWallet">Copy</button>
                    <a class="wallet-btn" href="/wallet.html">Open&nbsp;Wallet&nbsp;<span>→</span></a>
                </div>
                <span class="field-hint">Identity-bound keypair · held server-side · balance / faucet / payments on the Wallet page</span>
            </div>` : `
            <div class="dash-empty" role="note">
                <span class="label na">Wallet</span>
                <p>No wallet address returned for this session yet.</p>
            </div>`}`;

        const avatarImg = body.querySelector("img.github-avatar");
        if (avatarImg) {
            avatarImg.addEventListener("error", () => {
                const span = document.createElement("span");
                span.className = "github-avatar github-avatar--fallback";
                span.textContent = (name || "U").charAt(0).toUpperCase();
                span.setAttribute("aria-hidden", "true");
                avatarImg.replaceWith(span);
            });
        }

        const copyBtn = $("copyDashWallet");
        copyBtn?.addEventListener("click", async () => {
            try {
                await navigator.clipboard.writeText(address);
                copyBtn.textContent = "Copied ✓";
                setTimeout(() => { copyBtn.textContent = "Copy"; }, 1500);
            } catch (error) {
                console.error("Copy failed:", error);
            }
        });
    }
}

async function loadDashboard() {
    // All three endpoints are GETs and read-only; fire together, render as
    // they arrive. Session state owns the account card; the other two own
    // network/program — they render correctly logged-out too.
    const [me, health, program] = await Promise.all([
        AgentPayAuth.fetchMe(),
        getJson("/api/health"),
        getJson("/api/program/status"),
    ]);

    renderHealth(health);
    renderProgram(program);

    if (!me) {
        AgentPayAuth.renderLoginButton(githubLogin, null);
        renderLoggedOut();
        return;
    }

    AgentPayAuth.renderLoginButton(githubLogin, me);
    renderAccount(me);
}

loadDashboard();
