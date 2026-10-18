/*
 * PHASE 7 — REAL LEADERBOARD (frontend).
 *
 * Consumes EXACTLY ONE endpoint (read-only, owner-scoped):
 *   GET /api/agents/leaderboard
 *     -> 200  { success:true, agents:[…rows…], total, order }
 *     -> 401  { success:false, error:{ code:"NOT_AUTHENTICATED" } }
 *     -> 500  { success:false, error:{ code:"AGENT_STORE_ERROR"
 *          | "RIALO_ERROR", message } }
 *
 * HARD RULE (the whole point of this page): rows are rendered in the
 * EXACT order the server supplied. This file NEVER sorts, re-orders,
 * filters, or re-ranks rows. Backend ordering is authoritative.
 *
 * Whitelist of fields rendered per row — ONLY these (the backend DTO
 * carries nothing else; it holds no owner id, wallet address,
 * idempotency key, policy internals, raw artifacts, or reconciliation
 * evidence. Nothing classified here):
 *   agent_id, name, status, total_intent_count, confirmed_payment_count,
 *   confirmed_payment_volume_kelvin, confirmed_payment_volume_rlo,
 *   last_confirmed_at, pending_count, failed_count, unknown_count,
 *   reconciled_count
 *
 * Balance is deliberately NOT shown: the backend contract excludes it
 * (a fabricated zero would be worse than no column).
 *
 * No mock data: every value rendered comes from this one API response.
 * Every state is real: loading (static HTML), auth-required, empty
 * board, rows, unavailable/error. No QA/stub loader ships.
 *
 * Auth: AgentPayAuth (auth.js) owns the navbar chip and
 * body.is-authed — same discipline as dashboard.js; no session logic
 * duplicated here.
 */

const githubLogin = document.querySelector(".github-login");

const $ = (id) => document.getElementById(id);

/* ------------------------------------------------------------------ *
 * Formatting helpers (display-only; pure functions of API values)
 * ------------------------------------------------------------------ */

/* kelvin -> display currency. RLO is the public display unit
 * (kelvin / 1e9, same ratio as the backend uses for _rlo). Volume
 * columns show RLO because that is the human-meaningful unit; the raw
 * kelvin figure is intentionally NOT rendered by the board grid. */
function formatRlo(value) {
    const n = Number(value);
    if (!Number.isFinite(n)) return "—";
    return n.toLocaleString("en-US", { maximumFractionDigits: 6 });
}

/* POSIX-seconds timestamp -> compact human time. null -> { text:"—", title:"" }.
 * The source instant is exposed on the cell's title attribute (UTC ISO)
 * so the displayed local time is never taken at face value. */
function formatTime(posix) {
    if (posix === null || posix === undefined) return { text: "—", title: "" };
    const ms = Number(posix) * 1000;
    const date = new Date(ms);
    if (Number.isNaN(date.getTime())) return { text: "—", title: "" };
    const stamp = date.toLocaleString("en-US", {
        year: "numeric", month: "short", day: "numeric",
        hour: "2-digit", minute: "2-digit",
    });
    return { text: stamp, title: `UTC ${date.toISOString().replace("T", " ").slice(0, 19)}` };
}

/* Lifecycle status -> presentational tone token. The API supplies the
 * canonical lowercase name; this only maps it to a visual tone. */
function statusTone(status) {
    switch (String(status || "").toLowerCase()) {
        case "active": return "ok";
        case "draft": return "warn";
        case "paused": return "warn";
        case "disabled": return "bad";
        default: return "neutral";
    }
}

/* ------------------------------------------------------------------ *
 * State pills (dash-status-bar), reused from the dashboard vocabulary
 * ------------------------------------------------------------------ */

function setStatePill(kind, label) {
    const el = $("lbState");
    if (!el) return;
    el.className = "status " + kind;
    const text = el.querySelector(".status__label");
    if (text) text.textContent = label;
}

function setCount(value) {
    const el = $("lbCount");
    if (!el) return;
    el.textContent = value;
}

/* ------------------------------------------------------------------ *
 * Board body renderers (id: #lbBody)
 * ------------------------------------------------------------------ */

/* LOADING: the initial state ships in the static HTML (no flash of an
 * empty board); this helper exists so the Retry path can restore it. */
function renderLoading() {
    setStatePill("status--na", "Leaderboard — loading");
    setCount("—");
    const body = $("lbBody");
    if (!body) return;
    body.innerHTML = `
        <div class="dash-empty" role="status">
            <span class="label na">Loading…</span>
            <p>Reading your confirmed payment history.</p>
        </div>`;
}

/* AUTH-REQUIRED: the user is not signed in. */
function renderAuthRequired() {
    setStatePill("status--na", "Leaderboard — sign in");
    setCount("—");
    const body = $("lbBody");
    if (!body) return;
    body.innerHTML = `
        <div class="gated-note">
            <span class="badge">Auth&nbsp;required</span>
            <span>The leaderboard is owner-scoped: sign in with GitHub to see <em>your</em> agents and their confirmed payment history — no other users' agents can appear.</span>
            <a class="wallet-btn wallet-btn--solid" href="/auth/github">
                Login&nbsp;with&nbsp;GitHub
                <span>↗</span>
            </a>
        </div>`;
}

/* EMPTY: signed in, zero owned agents (or zero rows). Honest empty
 * state — never fabricated rows, with a route to create an agent. */
function renderEmpty() {
    setStatePill("status--on", "Leaderboard — empty");
    setCount("0");
    const body = $("lbBody");
    if (!body) return;
    body.innerHTML = `
        <div class="dash-empty" role="status">
            <span class="label na">No agents on the board</span>
            <p>There are no agents under this account yet — so there is nothing to rank. The board fills in automatically as you create agents and their payments confirm.</p>
            <a class="wallet-btn wallet-btn--solid" href="/agents">
                Open&nbsp;Agents&nbsp;
                <span>→</span>
            </a>
        </div>`;
}

/* ROWS: signed in, at least one agent. Rendered in the server's exact
 * order. Row rank number = server index (1-based) — presentation only,
 * identical to the supplied order; no sorting happens here. */
function renderRows(agents, orderStatement) {
    const esc = AgentPayAuth.escapeHtml;
    const count = agents.length;

    setStatePill("status--on", "Leaderboard — live");
    setCount(String(count));

    const rows = agents
        .map((agent, index) => {
            const rank = index + 1;
            const rankClass = rank === 1 ? " is-gold" : rank === 2 ? " is-silver" : rank === 3 ? " is-bronze" : "";
            const name = esc(agent.name ?? agent.agent_id ?? "—");
            const id = esc(agent.agent_id ?? "—");
            const status = String(agent.status ?? "—");
            const tone = statusTone(agent.status);
            const total = Number(agent.total_intent_count);
            const confirmed = Number(agent.confirmed_payment_count);
            const rlo = formatRlo(agent.confirmed_payment_volume_rlo);
            const last = formatTime(agent.last_confirmed_at);
            const pending = Number(agent.pending_count);
            const failed = Number(agent.failed_count);
            const unknown = Number(agent.unknown_count);
            const reconciled = Number(agent.reconciled_count);

            // Per-row "Activity" deep-link: the Activity page accepts a
            // ?agent= query param to pre-filter to one agent (existing
            // surface); the query string is the only navigation aid, and
            // it never exposes internals (the row's own agent_id is the
            // caller's own agent — safe to link).
            const activityHref = `/activity.html?agent=${encodeURIComponent(agent.agent_id)}`;

            return `
            <tr class="lb-row${rankClass}" data-rank="${rank}">
                <td class="lb-rank" scope="row"><span class="lb-rank__num">${rank}</span></td>
                <td class="lb-agent">
                    <span class="lb-agent__name" title="${id}">${name}</span>
                    <span class="lb-agent__id mono" title="${id}">${esc(id.slice(0, 8))}…</span>
                </td>
                <td class="lb-status"><span class="chip chip--${tone}">${esc(status)}</span></td>
                <td class="lb-num mono">${Number.isFinite(total) ? total : "—"}</td>
                <td class="lb-num mono">${Number.isFinite(confirmed) ? confirmed : "—"}</td>
                <td class="lb-num lb-num--vol mono" title="confirmed_payment_volume_rlo">${rlo} <span class="unit">RLO</span></td>
                <td class="lb-time mono${last.title ? " lb-time--has" : ""}"${last.title ? ` title="${esc(last.title)}"` : ""}>${esc(last.text)}</td>
                <td class="lb-num mono subtle">${Number.isFinite(pending) ? pending : "—"}</td>
                <td class="lb-num mono subtle">${Number.isFinite(failed) ? failed : "—"}</td>
                <td class="lb-num mono subtle">${Number.isFinite(unknown) ? unknown : "—"}</td>
                <td class="lb-num mono subtle">${Number.isFinite(reconciled) ? reconciled : "—"}</td>
                <td class="lb-actions"><a class="dash-inline-link lb-activity-link" href="${activityHref}">Activity&nbsp;→</a></td>
            </tr>`;
        })
        .join("");

    const orderNote = orderStatement
        ? `<span class="field-hint lb-order-note">Server order: <span class="mono">${esc(orderStatement)}</span></span>`
        : "";

    const body = $("lbBody");
    if (!body) return;
    body.innerHTML = `
        <div class="lb-wrap">
        <table class="lb-table" aria-label="Agent leaderboard">
            <thead>
                <tr>
                    <th scope="col" class="lb-rank">#</th>
                    <th scope="col">Agent</th>
                    <th scope="col">Status</th>
                    <th scope="col" class="lb-num">Total</th>
                    <th scope="col" class="lb-num">Confirmed</th>
                    <th scope="col" class="lb-num">Volume</th>
                    <th scope="col">Last<br>confirmed</th>
                    <th scope="col" class="lb-num subtle">Pending</th>
                    <th scope="col" class="lb-num subtle">Failed</th>
                    <th scope="col" class="lb-num subtle">Unknown</th>
                    <th scope="col" class="lb-num subtle">Reconciled</th>
                    <th scope="col" class="lb-actions"><span class="sr-only">Row actions</span></th>
                </tr>
            </thead>
            <tbody>
                ${rows}
            </tbody>
        </table>
        ${orderNote}
        </div>`;
}

/* ERROR / UNAVAILABLE: signed in but the board could not be read
 * completely (500 AGENT_STORE_ERROR / RIALO_ERROR, network failure, or
 * unparseable payload). Fail-closed: never a partial or fake board. */
function renderError(fallbackCode) {
    setStatePill("status--off", "Leaderboard — unavailable");
    setCount("—");
    const body = $("lbBody");
    if (!body) return;
    body.innerHTML = `
        <div class="dash-empty" role="alert">
            <span class="label na">Board unavailable</span>
            <p>The leaderboard could not be read completely this moment. A partial board is never shown — retry in a moment. Your data is intact; only this read failed.</p>
            <div class="lb-error-actions">
                <button type="button" class="wallet-btn wallet-btn--solid" id="lbRetry">Retry&nbsp;↻</button>
                <a class="wallet-btn" href="/agents">Open\u00a0Agents\u00a0<span>→</span></a>
            </div>
            ${fallbackCode ? `<span class="field-hint lb-error-code mono">${AgentPayAuth.escapeHtml(fallbackCode)}</span>` : ""}
        </div>`;

    $("lbRetry")?.addEventListener("click", () => {
        // Re-run the whole page flow: re-check session, re-fetch board.
        // This is the ONLY retry path; no stale in-memory rows are kept.
        // Restore the static loading view first (no gap state).
        renderLoading();
        loadLeaderboard();
    });
}

/* ------------------------------------------------------------------ *
 * Network (single endpoint, GET only — no POST/PUT/DELETE ever fires
 * from this page; no artifact mutation, no payment, no faucet).
 * ------------------------------------------------------------------ */

async function fetchLeaderboard() {
    try {
        const response = await fetch("/api/agents/leaderboard", {
            method: "GET",
            credentials: "same-origin",
            cache: "no-store",
        });
        const payload = await response.json().catch(() => null);
        return { status: response.status, ok: response.ok, payload };
    } catch (error) {
        // network failure (offline, DNS, 502/503/504 without JSON body)
        console.error("Failed to load leaderboard:", error);
        return { status: 0, ok: false, payload: null };
    }
}

/* ------------------------------------------------------------------ *
 * Page flow
 * ------------------------------------------------------------------ */

async function loadLeaderboard() {
    // Session state owns the navbar chip (auth.js) — keep it in sync
    // before the board decision, exactly like dashboard.js.
    const me = await AgentPayAuth.fetchMe();
    if (githubLogin) AgentPayAuth.renderLoginButton(githubLogin, me);

    // AUTH-REQUIRED: no session -> do not even call the board endpoint
    // (it would 401 anyway); show the sign-in state directly.
    if (!me) {
        renderAuthRequired();
        return;
    }

    const { status, ok, payload } = await fetchLeaderboard();

    if (status === 401) {
        // Session dropped mid-page: treat as auth-required.
        renderAuthRequired();
        return;
    }

    if (!ok) {
        const code = payload?.error?.code || (status === 0 ? "NETWORK_UNREACHABLE" : `HTTP_${status}`);
        renderError(code);
        return;
    }

    // 200, but the payload must be well-formed (fail-closed on a
    // malformed body: an array is required, and each row must be an
    // object — never a half-shaped board).
    if (!payload || payload.success !== true || !Array.isArray(payload.agents)
        || !payload.agents.every((row) => row && typeof row === "object")) {
        renderError("MALFORMED_RESPONSE");
        return;
    }

    // Order: payload.agents is consumed VERBATIM, in array order.
    // NO sort, NO filter, NO re-rank — the server is authoritative.
    const agents = payload.agents;

    if (agents.length === 0) {
        renderEmpty();
        return;
    }

    renderRows(agents, payload.order);
}

loadLeaderboard().catch(() => renderError("NETWORK_UNREACHABLE"));