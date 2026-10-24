/*
 * RIALO AGENTPAY — REAL MARKETPLACE (frontend).
 *
 * Data source contract (the ONLY endpoints this page talks to — all real
 * task-engine routes, no mocks, no fabricated rows):
 *   GET  /api/tasks/open            -> { tasks:[summary…], count }
 *   GET  /api/tasks/{id}            -> { task:{…}, reservation_status, is_owner, is_worker }
 *   GET  /api/agents                -> agent list for the create form (owners)
 *   POST /api/tasks                 -> create   { agent_id,title,description,acceptance_criteria,reward_rlo }
 *   POST /api/tasks/{id}/claim      -> { recipient_address }
 *   POST /api/tasks/{id}/submit     -> { url, notes }
 *   POST /api/tasks/{id}/review     -> { action:"approve"|"reject"|"request_changes", notes }
 *   POST /api/tasks/{id}/cancel     -> {}
 *
 * Every state is real: loading (static HTML), signed-out (list stays
 * public per backend visibility rules; owner tools hidden), empty board,
 * rows, detail drawer, per-action errors surfaced verbatim from the API
 * error { code, message }. No QA/stub loader ships.
 *
 * Auth: AgentPayAuth (auth.js) owns the navbar chip and body.is-authed —
 * same discipline as leaderboard.js/dashboard.js; no session logic here.
 *
 * Escaping: every interpolated string passes AgentPayAuth.escapeHtml.
 */

const $ = (id) => document.getElementById(id);
const esc = (v) => AgentPayAuth.escapeHtml(String(v ?? ""));

function fmtRlo(v) {
    const n = Number(v);
    if (!Number.isFinite(n)) return "—";
    return n.toLocaleString("en-US", { maximumFractionDigits: 9 });
}

/* Backend status strings are Debug-lowercase ("inprogress",
 * "underreview", …), with older payloads possibly using spaces. Normalize
 * to the kebab tokens the action matrix and CSS understand; raw status
 * values always flow untouched into API calls/logs. */
function statusToken(status) {
    const normalized = String(status ?? "").trim().toLowerCase().replace(/[\s_]+/g, "-");
    const aliases = {
        inprogress: "in-progress",
        underreview: "under-review",
        revisionrequested: "revision-requested",
        paymentpending: "payment-pending",
        paymentfailed: "payment-failed",
    };
    return aliases[normalized] || normalized;
}

function statusLabel(status) {
    return statusToken(status).replace(/-/g, " ");
}

function fmtDate(sec) {
    const n = Number(sec);
    if (!Number.isFinite(n) || n <= 0) return "—";
    try {
        return new Date(n * 1000).toISOString().replace("T", " ").slice(0, 16) + "Z";
    } catch {
        return "—";
    }
}

async function api(path, opts = {}) {
    const res = await fetch(path, {
        credentials: "same-origin",
        cache: "no-store",
        headers: opts.body ? { "Content-Type": "application/json" } : {},
        ...opts,
        body: opts.body ? JSON.stringify(opts.body) : undefined,
    });
    let data = null;
    try { data = await res.json(); } catch { /* non-JSON error body */ }
    return { ok: res.ok, status: res.status, data };
}

function apiErrText(data, status) {
    const code = data?.data?.error?.code || data?.error?.code || "";
    const msg = data?.data?.error?.message || data?.error?.message || "";
    if (code || msg) return `${code || "ERROR"}${msg ? ": " + msg : ""}`;
    return `HTTP ${status}`;
}

/* ------------------------------------------------------------------ *
 * LIST
 * ------------------------------------------------------------------ */

let LAST_LIST = [];

async function loadTasks() {
    const body = $("mkBody");
    const { ok, status, data } = await api("/api/tasks/open");

    if (!ok) {
        $("mkState").innerHTML =
            `<span class="status__dot" aria-hidden="true"></span>` +
            `<span class="status__label">Marketplace — unavailable</span>`;
        $("mkCount").textContent = "—";
        body.innerHTML = `
            <div class="dash-empty" role="alert">
                <span class="label na">Task engine unavailable</span>
                <p>${esc(apiErrText(data, status))}</p>
                <p><button class="wallet-btn wallet-btn--sm" id="mkRetry">Retry</button></p>
            </div>`;
        const r = document.getElementById("mkRetry");
        if (r) r.addEventListener("click", () => { resetListLoading(); loadTasks(); });
        return;
    }

    const tasks = Array.isArray(data?.tasks) ? data.tasks : [];
    LAST_LIST = tasks;
    $("mkCount").textContent = String(tasks.length);

    if (tasks.length === 0) {
        $("mkState").innerHTML =
            `<span class="status__dot" aria-hidden="true"></span>` +
            `<span class="status__label">Marketplace — empty</span>`;
        body.innerHTML = `
            <div class="dash-empty" role="status">
                <span class="label na">No open tasks</span>
                <p>Nothing on the board right now. Owners: create one below${document.body.classList.contains("is-authed") ? "" : " after signing in"}.</p>
            </div>`;
        return;
    }

    $("mkState").innerHTML =
        `<span class="status__dot" aria-hidden="true"></span>` +
        `<span class="status__label">Marketplace — live</span>`;

    body.innerHTML = `
        <div class="mk-list">
            ${tasks.map((t) => `
                <div class="mk-row" role="button" tabindex="0" data-task="${esc(t.task_id)}">
                    <div class="mk-row__main">
                        <p class="mk-row__title">${esc(t.title)}</p>
                        <div class="mk-row__meta">
                            <span class="mono">${esc(t.task_id)}</span>
                            <span>owner: ${esc(t.owner_name)}</span>
                            <span class="mk-pill mk-pill--${esc(statusToken(t.status))}">${esc(statusLabel(t.status))}</span>
                            <span>${esc(fmtDate(t.created_at))}</span>
                        </div>
                    </div>
                    <div class="mk-row__reward">${esc(fmtRlo(t.reward_rlo))} <span class="unit">RLO</span></div>
                </div>`).join("")}
        </div>`;

    body.querySelectorAll(".mk-row").forEach((row) => {
        const open = () => openDetail(row.getAttribute("data-task"));
        row.addEventListener("click", open);
        row.addEventListener("keydown", (e) => {
            if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); }
        });
    });
}

function resetListLoading() {
    $("mkState").innerHTML =
        `<span class="status__dot" aria-hidden="true"></span>` +
        `<span class="status__label">Marketplace — loading</span>`;
    $("mkCount").textContent = "—";
    $("mkBody").innerHTML = `
        <div class="dash-empty" role="status">
            <span class="label na">Loading…</span>
            <p>Reading the open task board.</p>
        </div>`;
}

/* ------------------------------------------------------------------ *
 * DETAIL + ACTIONS
 * ------------------------------------------------------------------ */

let CURRENT_DETAIL = null;

async function openDetail(taskId) {
    if (!taskId) return;
    const card = $("mkDetailCard");
    const body = $("detailBody");
    $("detailLabel").textContent = taskId;
    $("detailStatus").textContent = "loading…";
    card.hidden = false;
    body.innerHTML = `<div class="dash-empty" role="status"><span class="label na">Loading…</span></div>`;
    card.scrollIntoView({ behavior: "smooth", block: "nearest" });

    const { ok, status, data } = await api(`/api/tasks/${encodeURIComponent(taskId)}`);
    if (!ok) {
        $("detailStatus").textContent = "unavailable";
        body.innerHTML = `
            <div class="dash-empty" role="alert">
                <span class="label na">Cannot load task</span>
                <p>${esc(apiErrText(data, status))}</p>
            </div>`;
        return;
    }

    const t = data.task || {};
    CURRENT_DETAIL = { id: t.task_id, isOwner: !!data.is_owner, isWorker: !!data.is_worker, status: t.status };
    $("detailStatus").textContent = t.status ? statusLabel(t.status) : "?";
    renderDetail(t);
}

function renderDetail(t) {
    const body = $("detailBody");
    body.innerHTML = `
        <div class="mk-detail-grid">
            <div>
                <span class="label">Title</span>
                <p class="mk-row__title">${esc(t.title)}</p>
            </div>
            <div>
                <span class="label">Description</span>
                <p class="field-hint">${esc(t.description)}</p>
            </div>
            <div>
                <span class="label">Acceptance criteria</span>
                <p class="field-hint">${esc(t.acceptance_criteria)}</p>
            </div>
            <div class="mk-row__meta">
                <span>Reward: <strong>${esc(fmtRlo(t.reward_rlo))} RLO</strong></span>
                <span>Owner: ${esc(t.owner_name)}</span>
                ${t.worker_name ? `<span>Worker: ${esc(t.worker_name)}</span>` : ""}
                <span>Created: ${esc(fmtDate(t.created_at))}</span>
                <span>Updated: ${esc(fmtDate(t.updated_at))}</span>
            </div>
            ${t.submission_url ? `<div><span class="label">Submission</span>
                <p class="field-hint"><a class="dash-inline-link" href="${esc(t.submission_url)}" rel="noopener noreferrer">${esc(t.submission_url)}</a></p>
                ${t.submission_notes ? `<p class="field-hint">${esc(t.submission_notes)}</p>` : ""}
            </div>` : ""}
            ${t.review_notes ? `<div><span class="label">Review notes</span><p class="field-hint">${esc(t.review_notes)}</p></div>` : ""}
            ${t.payment_tx_signature ? `<div><span class="label">Payment tx</span><p class="field-hint mono">${esc(t.payment_tx_signature)}</p></div>` : ""}
            ${t.payment_error ? `<div><span class="label">Payment error</span><p class="field-hint">${esc(t.payment_error)}</p></div>` : ""}
        </div>
        <div class="mk-actions" id="mkActionArea"></div>`;

    const area = document.getElementById("mkActionArea");
    const d = CURRENT_DETAIL;
    // statusToken(): CSS token only. d.status stays the RAW backend string.
    const st = statusToken(d.status);

    if (!document.body.classList.contains("is-authed")) {
        area.innerHTML = `<a class="wallet-btn wallet-btn--sm github-login" href="/auth/github">Sign in with GitHub to act</a>`;
        return;
    }

    // Action matrix mirrors the backend EXACTLY (tasks.rs can_transition +
    // role checks) — a button is rendered only when the transition it
    // triggers is actually legal server-side (verified 2026-10-17):
    //   Open → InProgress | Cancelled
    //   InProgress → Submitted            (worker: submit)
    //   Submitted → UnderReview | PaymentPending   (owner: approve)
    //   UnderReview → Approved | Rejected | RevisionRequested (owner)
    // Claim: Open + not-owner + recipient address (worker).

    // Worker path
    if (st === "open" && !d.isOwner) {
        area.innerHTML = `
            <input id="mkClaimAddr" class="input mono" placeholder="Your RLO recipient address" style="min-width:280px">
            <button class="wallet-btn wallet-btn--sm wallet-btn--solid" id="mkClaim">Claim task</button>`;
        document.getElementById("mkClaim").addEventListener("click", () => act("claim"));
    } else if (st === "in-progress" && d.isWorker) {
        area.innerHTML = `
            <input id="mkSubUrl" class="input mono" placeholder="Submission URL" style="min-width:280px">
            <input id="mkSubNotes" class="input" placeholder="Notes (optional)" style="min-width:220px">
            <button class="wallet-btn wallet-btn--sm wallet-btn--solid" id="mkSubmit">Submit work</button>`;
        document.getElementById("mkSubmit").addEventListener("click", () => act("submit"));
    }

    // Owner path
    if (d.isOwner) {
        if (st === "submitted") {
            // Approve (Submitted → PaymentPending payout bridge) is legal.
            // Reject from Submitted is NOT (backend: Submitted→Rejected is
            // not in can_transition) — shown only at "under review".
            area.insertAdjacentHTML("beforeend", `
                <input id="mkRevNotes" class="input" placeholder="Review notes" style="min-width:220px">
                <button class="wallet-btn wallet-btn--sm wallet-btn--solid" id="mkApprove">Approve &amp; pay</button>`);
            document.getElementById("mkApprove").addEventListener("click", () => act("review", "approve"));
            area.insertAdjacentHTML("beforeend", `
                <span class="field-hint">Visible after the submission enters review (“under review”) — the engine rejects a direct Submitted→Rejected move.</span>`);
        } else if (st === "under-review") {
            area.insertAdjacentHTML("beforeend", `
                <input id="mkRevNotes" class="input" placeholder="Review notes" style="min-width:220px">
                <button class="wallet-btn wallet-btn--sm wallet-btn--solid" id="mkApprove">Approve</button>
                <button class="wallet-btn wallet-btn--sm wallet-btn--danger" id="mkReject">Reject</button>`);
            document.getElementById("mkApprove").addEventListener("click", () => act("review", "approve"));
            document.getElementById("mkReject").addEventListener("click", () => act("review", "reject"));
        }
        // F2: cancel is legal ONLY from Open (can_transition(*, Cancelled)).
        if (st === "open") {
            area.insertAdjacentHTML("beforeend", `<button class="wallet-btn wallet-btn--sm wallet-btn--danger" id="mkCancel">Cancel task</button>`);
            const c = document.getElementById("mkCancel");
            if (c) c.addEventListener("click", () => act("cancel"));
        }
    }

    if (!area.children.length) {
        area.innerHTML = `<span class="field-hint">No actions available for your role at status “${esc(statusLabel(d.status))}”.</span>`;
    }
}

async function act(kind, sub) {
    const d = CURRENT_DETAIL;
    if (!d) return;
    let path = `/api/tasks/${encodeURIComponent(d.id)}`;
    const actionSuffix = { claim: "/claim", submit: "/submit", review: "/review", cancel: "/cancel" }[kind];
    if (!actionSuffix) return;
    path += actionSuffix;
    let payload = {};
    if (kind === "claim") { payload = { recipient_address: document.getElementById("mkClaimAddr").value.trim() }; }
    else if (kind === "submit") { payload = { url: document.getElementById("mkSubUrl").value.trim(), notes: document.getElementById("mkSubNotes").value.trim() }; }
    else if (kind === "review") { payload = { action: sub, notes: (document.getElementById("mkRevNotes")?.value || "").trim() }; }

    const btns = document.querySelectorAll("#mkActionArea .wallet-btn");
    btns.forEach((b) => (b.disabled = true));

    const { ok, status, data } = await api(path, { method: "POST", body: payload });

    if (!ok) {
        const errEl = document.createElement("p");
        errEl.className = "field-hint";
        errEl.setAttribute("role", "alert");
        errEl.textContent = apiErrText(data, status);
        document.getElementById("mkActionArea").appendChild(errEl);
        btns.forEach((b) => (b.disabled = false));
        return;
    }
    // Success: refresh detail + list from the engine (server verdict shown).
    await openDetail(d.id);
    await loadTasks();
}

/* ------------------------------------------------------------------ *
 * CREATE (owners)
 * ------------------------------------------------------------------ */

async function setupCreate(authed = document.body.classList.contains("is-authed")) {
    const card = $("mkCreateCard");
    if (!authed) {
        card.hidden = true;
        return;
    }
    card.hidden = false;
    // Load agents for the picker (owner scope enforced server-side).
    const { ok, data } = await api("/api/agents");
    const sel = $("mkAgent");
    if (!ok || !Array.isArray(data?.agents) || data.agents.length === 0) {
        sel.innerHTML = `<option value="">— no agents —</option>`;
        sel.disabled = true;
        $("mkAgentHint").textContent = "Create an agent first (Agents page) to offer tasks.";
        return;
    }
    sel.disabled = false;
    sel.innerHTML = data.agents
        .map((a) => `<option value="${esc(a.agent_id)}">${esc(a.name || a.agent_id)}</option>`)
        .join("");

    $("mkCreateForm").addEventListener("submit", async (e) => {
        e.preventDefault();
        const msg = $("mkCreateMsg");
        msg.removeAttribute("role");
        msg.textContent = "";
        const agentId = $("mkAgent").value.trim();
        const title = $("mkTitle").value.trim();
        const description = $("mkDesc").value.trim();
        const criteria = $("mkCriteria").value.trim();
        const reward = Number($("mkReward").value);
        if (!agentId || !title || !description || !criteria) {
            msg.setAttribute("role", "alert");
            msg.textContent = "Agent, title, description, and acceptance criteria are required.";
            return;
        }
        if (!Number.isFinite(reward) || reward <= 0) {
            msg.setAttribute("role", "alert");
            msg.textContent = "Reward must be greater than 0 RLO.";
            return;
        }
        const btn = $("mkCreateBtn");
        btn.disabled = true;
        const { ok: ok2, status, data } = await api("/api/tasks", {
            method: "POST",
            body: {
                agent_id: agentId,
                title,
                description,
                acceptance_criteria: criteria,
                reward_rlo: reward,
            },
        });
        btn.disabled = false;
        if (!ok2) {
            msg.setAttribute("role", "alert");
            msg.textContent = apiErrText(data, status);
            return;
        }
        msg.removeAttribute("role");
        msg.textContent = "Task created.";
        $("mkCreateForm").reset();
        await loadTasks();
    });
}

/* ------------------------------------------------------------------ *
 * BOOT
 * ------------------------------------------------------------------ */

document.getElementById("detailClose").addEventListener("click", () => {
    $("mkDetailCard").hidden = true;
    CURRENT_DETAIL = null;
});

async function boot() {
    // The board itself is public; only the navbar chip and owner tools
    // depend on the session. Hydrate auth BEFORE rendering any state that
    // keys off body.is-authed (otherwise an existing session looks like a
    // logout and the create card stays hidden).
    const githubLogin = document.querySelector(".github-login");
    let authed = false;
    try {
        const me = await AgentPayAuth.fetchMe();
        authed = AgentPayAuth.renderLoginButton(githubLogin, me);
    } catch (error) {
        console.error("Failed to load marketplace auth state:", error);
        AgentPayAuth.renderLoginButton(githubLogin, null);
    }

    await loadTasks();
    await setupCreate(authed);
}

boot().catch((error) => {
    console.error("Marketplace boot failed:", error);
    $("mkState").innerHTML =
        `<span class="status__dot" aria-hidden="true"></span>` +
        `<span class="status__label">Marketplace — unavailable</span>`;
});
