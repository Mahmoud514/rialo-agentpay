/*
 * Activity page (Phase 7 Step 1): owner-scoped per-agent payment history.
 *
 * A single dedicated surface keyed by `?agent=<agent_id>`, reached from each
 * agent card on the Agents page. It consumes ONE existing endpoint and
 * NOTHING else:
 *
 *   GET /api/agents/{id}/activity
 *
 * …with the server's documented filters (state, principal, recipient,
 * amount_kelvin, created_at_gte/lt) and cursor pagination (`limit`,
 * `cursor`). The server owns ordering (created_at DESC, tie-break
 * key_hex ASC) — this page NEVER re-sorts, NEVER paginates by offset, and
 * NEVER mutates any agent, policy, intent, credential, wallet, or on-chain
 * state. Every value rendered below is a field from the activity DTO; the
 * raw response blob is never shown (the server already whitelists it away).
 *
 * Honesty rules (unchanged project-wide):
 *   - unavailable data renders as an explicit empty/error state, never a
 *     simulated row;
 *   - a 500 (AGENT_STORE_ERROR) is fail-closed: we never render a partial
 *     history, and offer one retry;
 *   - ownership is a server concept — the server answers 404 for agents
 *     that are not the caller's, and we surface that indistinguishably.
 *
 * Auth/nav/chip belong to AgentPayAuth + AgentPayNav — not duplicated here.
 */

const AgentPayActivity = (() => {
    const $ = (id) => document.getElementById(id);
    const esc = AgentPayAuth.escapeHtml;

    const PAGE_SIZE = 20; // server default; limit cap is 100

    // state -> status tone + human label (6 canonical states)
    const STATE_META = {
        pending:           { tone: "status--na",   label: "Pending" },
        confirmed:         { tone: "status--on",   label: "Confirmed" },
        failed:            { tone: "status--off",  label: "Failed" },
        unknown:           { tone: "status--warn", label: "Unknown" },
        reconciled_paid:   { tone: "status--on",   label: "Reconciled · paid" },
        reconciled_absent: { tone: "status--na",   label: "Reconciled · absent" },
    };

    // ---------------------------------------------------------------------
    // PARAMS
    // ---------------------------------------------------------------------

    function agentIdFromQuery() {
        const id = new URLSearchParams(window.location.search).get("agent");
        return id ? id.trim() : "";
    }

    // ---------------------------------------------------------------------
    // API (read-only; mirrors the agents.js fetch helper)
    // ---------------------------------------------------------------------

    async function api(path) {
        try {
            const response = await fetch(path, {
                method: "GET",
                credentials: "same-origin",
                cache: "no-store",
            });
            const data = await response.json().catch(() => null);
            return { status: response.status, data };
        } catch (error) {
            console.error(`GET ${path} failed:`, error);
            return { status: 0, data: null };
        }
    }

    // ---------------------------------------------------------------------
    // FORMATTERS
    // ---------------------------------------------------------------------

    function fmtTs(unix) {
        if (!Number.isFinite(unix)) return "—";
        return new Date(unix * 1000).toLocaleString("en-GB", {
            year: "numeric", month: "short", day: "2-digit",
            hour: "2-digit", minute: "2-digit", second: "2-digit",
            timeZone: "UTC",
        }) + " UTC";
    }

    function fmtRlo(rlo, kelvin) {
        if (Number.isFinite(rlo)) {
            return `${rlo.toLocaleString("en-US", { maximumFractionDigits: 9 })} RLO`;
        }
        if (Number.isFinite(kelvin)) {
            return `${(kelvin / 1_000_000_000).toLocaleString("en-US", { maximumFractionDigits: 9 })} RLO`;
        }
        return "—";
    }

    // Whitelisted correlation: the DTO exposes the idempotency slot (always)
    // and the intent id (v2 records only). The slot is a hex-encoded
    // idempotency key — decoded for display, never stored or sent anywhere.
    function hexToText(hex) {
        const s = String(hex || "");
        if (!s || s.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(s)) return null;
        const bytes = [];
        for (let i = 0; i < s.length; i += 2) {
            const b = parseInt(s.slice(i, i + 2), 16);
            if (b > 0x7f) return null; // not printable ASCII: keep the raw form
            bytes.push(b);
        }
        return String.fromCharCode.apply(null, bytes);
    }

    function correlationLabel(item) {
        if (item.intent_id) return `intent ${item.intent_id}`;
        if (item.idempotency_slot) {
            const decoded = hexToText(item.idempotency_slot);
            const label = decoded || item.idempotency_slot;
            return `slot ${label}`;
        }
        return null;
    }

    function principalLabel(kind) {
        if (kind === "agent") return "by agent";
        if (kind === "owner") return "by owner";
        return "owner"; // v1 records are owner-principal by construction
    }

    // ---------------------------------------------------------------------
    // FILTER SANITIZATION (re-validate the server's contract client-side)
    // ---------------------------------------------------------------------

    const STATE_VALUES = new Set(Object.keys(STATE_META));
    const PRINCIPAL_VALUES = new Set(["owner", "agent"]);
    const RECIPIENT_RE = /^[A-Za-z0-9]{32,44}$/;

    function sanitizeFilters(raw) {
        const out = {};
        if (STATE_VALUES.has(raw.state)) out.state = raw.state;
        if (PRINCIPAL_VALUES.has(raw.principal)) out.principal = raw.principal;
        if (RECIPIENT_RE.test(raw.recipient)) out.recipient = raw.recipient;
        out.amount_kelvin = decodeKelvin(raw.amount);
        out.created_at_gte = dtToUnix(raw.from);
        out.created_at_lt = dtToUnix(raw.to);
        return out;
    }

    // Client RLO input -> server integer kelvin (u64). Returns null on any
    // non-positive / non-finite / sub-kelvin value so we never send a
    // param the server would reject — and flag it to the user instead.
    function decodeKelvin(text) {
        const t = (text || "").trim();
        if (t === "") return null;
        const n = Number(t);
        if (!Number.isFinite(n) || n <= 0) return null;
        const kelvin = Math.round(n * 1_000_000_000);
        if (!Number.isSafeInteger(kelvin) || kelvin < 1) return null;
        return kelvin;
    }

    function dtToUnix(value) {
        if (!value) return null;
        const s = String(value).trim();
        // datetime-local carries no timezone; the filter is labelled UTC,
        // so parse it as UTC (append Z) rather than the browser's local zone.
        const ms = Date.parse(/:\d{2}$/.test(s) ? `${s}Z` : `${s}:00Z`);
        if (Number.isNaN(ms)) return null;
        return Math.floor(ms / 1000);
    }

    function buildQuery(filters, cursor) {
        const params = new URLSearchParams();
        params.set("limit", String(PAGE_SIZE));
        if (cursor) params.set("cursor", cursor);
        for (const key of ["state", "principal", "recipient"]) {
            if (filters[key]) params.set(key, filters[key]);
        }
        if (Number.isSafeInteger(filters.amount_kelvin) && filters.amount_kelvin > 0) {
            params.set("amount_kelvin", String(filters.amount_kelvin));
        }
        if (Number.isSafeInteger(filters.created_at_gte)) params.set("created_at_gte", String(filters.created_at_gte));
        if (Number.isSafeInteger(filters.created_at_lt)) params.set("created_at_lt", String(filters.created_at_lt));
        return params.toString();
    }

    // ---------------------------------------------------------------------
    // RENDER HELPERS
    // ---------------------------------------------------------------------

    const statusPill = (tone, label) =>
        `<span class="status ${tone}"><span class="status__dot" aria-hidden="true"></span>` +
        `<span class="status__label">${esc(label)}</span></span>`;

    function setPageStatus(elmId, tone, label) {
        const el = $(elmId);
        if (!el) return;
        el.className = `status ${tone}`;
        el.innerHTML = `<span class="status__dot" aria-hidden="true"></span><span class="status__label">${esc(label)}</span>`;
    }

    function rowHtml(item) {
        const meta = STATE_META[item.state] || { tone: "status--na", label: item.state || "unknown" };
        const sig = item.tx_signature;
        const recon =
            item.reconciliation &&
            item.reconciliation.outcome &&
            item.state !== "failed"
                ? ` · ${item.reconciliation.method || "reconciled"}: ${item.reconciliation.outcome}`
                : "";
        const fail = item.failure && item.failure.code
            ? item.failure.code + (item.failure.http_status ? ` · ${item.failure.http_status}` : "")
            : null;
        const authz = item.authz_bound === true ? `<span class="act-authz">policy-bound</span>` : "";
        const corr = correlationLabel(item);

        const sigCell =
            sig
                ? `<span class="act-row__sig mono" title="transaction signature: ${esc(sig)}">${esc(sig)}</span>`
                : `<span class="act-row__sig mono">${fail ? "" : "no signature"}</span>`;
        const corrContent = [corr, fail].filter(Boolean).join(" · ");
        const corrLabel = fail
            ? `${corr ? corr + " · " : ""}${fail} (failure)`
            : "intent / idempotency correlation";
        const corrCell = corrContent
            ? `<span class="act-row__corr mono" title="${esc(corrLabel)}">${esc(corrContent)}</span>`
            : `<span class="act-row__corr mono"></span>`;

        return `
        <div class="act-row" role="listitem">
            <span class="act-row__time" title="created ${esc(fmtTs(item.created_at))} · updated ${esc(fmtTs(item.updated_at))}">${esc(fmtTs(item.created_at))}</span>
            <span class="act-row__amount">${esc(fmtRlo(item.amount_rlo, item.amount_kelvin))}</span>
            <span class="act-row__state">${statusPill(meta.tone, meta.label + recon)}</span>
            <span class="act-row__recipient mono" title="recipient (owner-only field)">${esc(item.recipient || "—")}</span>
            <span class="act-row__principal">${esc(principalLabel(item.principal_kind))}${authz ? " " + authz : ""}</span>
            ${sigCell}
            ${corrCell}
        </div>`;
    }

    // ---------------------------------------------------------------------
    // FEED STATE MACHINE
    // ---------------------------------------------------------------------

    // The column legend — static labels, same seven columns as .act-row.
    // Rendered once at the top of the rows container (inside the scroll
    // wrapper on narrow viewports, so it scrolls in lockstep with rows).
    const FEED_HEAD = `
            <div class="act-head" aria-hidden="true">
                <span>Created (UTC)</span>
                <span>Amount</span>
                <span>State</span>
                <span>Recipient</span>
                <span>Principal</span>
                <span>Signature / Failure</span>
                <span>Correlation</span>
            </div>`;
    let agentId = "";
    let filters = {};
    let nextCursor = null;
    let feedRows = [];
    let totalSeen = 0;
    let reqSeq = 0;
    let lastError = null; // {status, code, message}

    function setFeed(elmId, html) {
        const el = $(elmId);
        if (el) el.innerHTML = html;
    }

    function renderCount(label) {
        const el = $("feedCount");
        if (!el) return;
        el.className = "status status--na";
        el.innerHTML = `<span class="status__label">${esc(String(label))}</span>`;
    }

    function setLoading() {
        lastError = null;
        setPageStatus("activityState", "status--na", "Activity — loading");
        renderCount("Loading");
        setFeed("feedBody", `<div class="dash-empty" role="status"><span class="label na">Loading…</span><p>Reading the replay ledger.</p></div>`);
        $("loadMore")?.setAttribute("hidden", "");
    }

    function renderEmpty() {
        setPageStatus("activityState", "status--na", "No activity");
        renderCount(`0 of ${totalSeen}`);
        setFeed("feedBody", `
            <div class="dash-empty" role="note">
                <span class="label na">No activity</span>
                <p>No payment intents match. This is a real, empty feed — not a
                placeholder. Activity appears here only after a payment intent
                exists for this agent.</p>
            </div>`);
        $("loadMore")?.setAttribute("hidden", "");
    }

    function renderGated() {
        lastError = { status: 401, code: "NOT_AUTHENTICATED" };
        setPageStatus("activityState", "status--warn", "Not signed in");
        renderCount("Not signed in");
        setFeed("feedBody", `
            <div class="gated-note">
                <span class="badge">Auth&nbsp;required</span>
                <span>Sign in with GitHub to view${agentId ? " this agent's" : " the agent's"} activity history.</span>
                <a class="wallet-btn wallet-btn--solid" href="/auth/github">
                    Login&nbsp;with&nbsp;GitHub
                    <span>↗</span>
                </a>
            </div>`);
        $("loadMore")?.setAttribute("hidden", "");
    }

    function renderNotFound() {
        lastError = { status: 404, code: "AGENT_NOT_FOUND" };
        setPageStatus("activityState", "status--off", "Not available");
        renderCount("Not available");
        setFeed("feedBody", `
            <div class="dash-empty" role="alert">
                <span class="label na">Not available</span>
                <p>This agent isn't available on the AgentPay service. It may
                have been deleted, or it may not belong to the signed-in
                account — the service answers the same "not found" for both,
                by design.</p>
                <a class="wallet-btn wallet-btn--solid" href="/agents.html">
                    Back&nbsp;to&nbsp;Agents
                    <span>→</span>
                </a>
            </div>`);
        $("loadMore")?.setAttribute("hidden", "");
    }

    function renderInvalid() {
        setPageStatus("activityState", "status--warn", "Invalid filter");
        renderCount("Invalid");
        setFeed("feedBody", `
            <div class="dash-empty" role="alert">
                <span class="label na">Filter invalid</span>
                <p>The activity service rejected this filter query
                (${esc(lastError?.code || "ACTIVITY_REQUEST_INVALID")}).
                Reset the filters and try again.</p>
                <button type="button" class="wallet-btn wallet-btn--solid" id="resetFromError">
                    Reset&nbsp;filters
                </button>
            </div>`);
        $("loadMore")?.setAttribute("hidden", "");
        const btn = $("resetFromError");
        btn?.addEventListener("click", doReset);
    }

    function renderStoreError() {
        setPageStatus("activityState", "status--off", "Unavailable");
        renderCount("Unavailable");
        setFeed("feedBody", `
            <div class="dash-empty" role="alert">
                <span class="label na">Unavailable</span>
                <p>The activity ledger couldn't be read completely. A partial
                history is never shown — that would be a dangerous one. Retry
                below.</p>
                <button type="button" class="wallet-btn wallet-btn--solid" id="retryBtn">
                    Retry
                    <span>↻</span>
                </button>
            </div>`);
        $("loadMore")?.setAttribute("hidden", "");
        const btn = $("retryBtn");
        btn?.addEventListener("click", () => start(false));
    }

    function handleResult({ status, data }, { preserve, seq }) {
        // Stale-response guard FIRST: a newer request has already flown (its
        // reqSeq superseded this call's) while this response was in flight —
        // nothing it carries may touch the feed, error states included.
        if (seq !== reqSeq) return;

        if (status === 401) { renderGated(); return; }
        if (status === 404) { renderNotFound(); return; }

        // Network failure (status 0) or a failure to parse JSON: fail closed.
        if (status === 0 || !data) {
            lastError = { status: status || 500, code: (data && data.error && data.error.code) || "ACTIVITY_STORE_ERROR" };
            renderStoreError();
            return;
        }
        if (status === 400) {
            lastError = { status: 400, code: data?.error?.code || "ACTIVITY_REQUEST_INVALID", message: data?.error?.message };
            renderInvalid();
            return;
        }
        if (status === 500) {
            lastError = { status: 500, code: data?.error?.code || "AGENT_STORE_ERROR" };
            renderStoreError();
            return;
        }
        if (status !== 200 || !data.success || !Array.isArray(data.items)) {
            lastError = { status: status || 500, code: data?.error?.code || "AGENT_STORE_ERROR" };
            renderStoreError();
            return;
        }

        const items = data.items;
        nextCursor = data.next_cursor || null;

        if (preserve) {
            // append, de-duplicating by (agent_id, idempotency_slot) so a
            // overlapping cursor page can never duplicate a row
            const seenSlots = new Set(feedRows.map((r) => `${r.agent_id}|${r.idempotency_slot}`));
            for (const it of items) {
                const key = `${it.agent_id}|${it.idempotency_slot}`;
                if (seenSlots.has(key)) continue;
                seenSlots.add(key);
                feedRows.push(it);
            }
            totalSeen = feedRows.length;
        } else {
            feedRows = items.slice();
            totalSeen = items.length;
        }

        setFeed("feedBody", feedRows.length
            ? `<div class="act-rows" role="list">${FEED_HEAD}\n${feedRows.map(rowHtml).join("\n")}</div>`
            : "");

        if (feedRows.length > 0) {
            setPageStatus("activityState", "status--on", "Activity — live");
        }
        if (feedRows.length === 0) {
            renderEmpty();
            return;
        }
        renderCount(`${totalSeen}${nextCursor ? " · more" : ""}`);

        const more = $("loadMore");
        if (nextCursor) {
            more?.removeAttribute("hidden");
            $("loadMoreHint").textContent = "Cursor pagination · server order · no offset";
        } else {
            more?.setAttribute("hidden", "");
        }

        if (!preserve && feedRows.length < PAGE_SIZE) {
            // a short first page means there is no further cursor either
            nextCursor = null;
            more?.setAttribute("hidden", "");
        }
    }

    async function loadPage(preserve) {
        reqSeq += 1;
        const seq = reqSeq;
        // "Load more" (preserve=true) sends the cursor captured from the last
        // rendered page; a fresh start always begins at the head of the feed.
        const q = buildQuery(filters, preserve ? nextCursor : null);
        const { status, data } = await api(`/api/agents/${encodeURIComponent(agentId)}/activity?${q}`);
        handleResult({ status, data }, { preserve, seq });
        return seq;
    }

    function doReset() {
        $("fState").value = "";
        $("fPrincipal").value = "";
        $("fRecipient").value = "";
        $("fAmount").value = "";
        $("fFrom").value = "";
        $("fTo").value = "";
        const msg = $("filterMsg");
        if (msg) { msg.textContent = ""; msg.className = "agents-msg"; }
        start(true);
    }

    async function start(resetList) {
        if (!agentId) {
            setPageStatus("activityState", "status--na", "No agent selected");
            renderCount("No agent");
            return;
        }
        filters = readFilters();
        nextCursor = null;
        feedRows = [];
        totalSeen = 0;
        $("filterCard").hidden = false;
        setLoading();
        await loadPage(false);
    }

    function readFilters() {
        return sanitizeFilters({
            state: $("fState").value,
            principal: $("fPrincipal").value,
            recipient: ($("fRecipient").value || "").trim(),
            amount: $("fAmount").value,
            from: $("fFrom").value,
            to: $("fTo").value,
        });
    }

    function applyFiltersWithValidation() {
        const raw = {
            state: $("fState").value,
            principal: $("fPrincipal").value,
            recipient: ($("fRecipient").value || "").trim(),
            amount: $("fAmount").value,
            from: $("fFrom").value,
            to: $("fTo").value,
        };
        const msg = $("filterMsg");
        const problems = [];
        if (raw.state && !STATE_VALUES.has(raw.state)) problems.push("state");
        if (raw.principal && !PRINCIPAL_VALUES.has(raw.principal)) problems.push("principal");
        if (raw.recipient && !RECIPIENT_RE.test(raw.recipient)) problems.push("recipient (32–44 alphanumeric)");
        const amt = raw.amount.trim();
        if (amt && (decodeKelvin(amt) === null)) problems.push("amount (positive RLO)");
        const fromUs = dtToUnix(raw.from);
        const toUs = dtToUnix(raw.to);
        if (raw.from && fromUs === null) problems.push("from date");
        if (raw.to && toUs === null) problems.push("to date");
        if (fromUs !== null && toUs !== null && fromUs >= toUs) problems.push("from must be before to");

        if (problems.length) {
            msg.textContent = `Invalid: ${problems.join(", ")}. Nothing was sent.`;
            msg.className = "agents-msg bad";
            return;
        }
        msg.textContent = "";
        msg.className = "agents-msg";
        start(true);
    }

    // ---------------------------------------------------------------------
    // CONTEXT (agent identity block)
    // ---------------------------------------------------------------------

    async function renderContext(authed) {
        const chip = $("agentChip");
        const body = $("ctxBody");
        if (!authed) {
            if (chip) chip.textContent = "—";
            body.innerHTML = `
                <div class="gated-note">
                    <span class="badge">Auth&nbsp;required</span>
                    <span>Sign in with GitHub to view an agent's activity history.</span>
                    <a class="wallet-btn wallet-btn--solid" href="/auth/github">
                        Login&nbsp;with&nbsp;GitHub
                        <span>↗</span>
                    </a>
                </div>`;
            $("filterCard").setAttribute("hidden", "");
            return;
        }
        if (!agentId) {
            if (chip) chip.textContent = "none";
            body.innerHTML = `
                <div class="gated-note">
                    <span class="badge">Agent&nbsp;required</span>
                    <span>Pick an agent from the registry to see its payment history.</span>
                    <a class="wallet-btn wallet-btn--solid" href="/agents.html">
                        Open&nbsp;Agents
                        <span>→</span>
                    </a>
                </div>`;
            $("filterCard").setAttribute("hidden", "");
            return;
        }

        // Resolve the agent's owner-scoped record for the identity block.
        // (The feed itself is still served by /api/agents/{id}/activity.)
        const { status, data } = await api(`/api/agents/${encodeURIComponent(agentId)}`);
        if (status === 401) {
            // session died mid-flow; treat as gated
            renderContext(false);
            return;
        }
        if (status === 404 || status === 0 || !data || !data.success) {
            if (chip) chip.textContent = "not found";
            body.innerHTML = `
                <div class="dash-empty" role="alert">
                    <span class="label na">Agent not found</span>
                    <p>The agent “${esc(agentId)}” isn't available on the
                    AgentPay service for this account.</p>
                    <a class="wallet-btn wallet-btn--solid" href="/agents.html">
                        Back&nbsp;to&nbsp;Agents
                        <span>→</span>
                    </a>
                </div>`;
            $("filterCard").setAttribute("hidden", "");
            setPageStatus("activityState", "status--off", "Not available");
            renderCount("Not available");
            setFeed("feedBody", `<div class="dash-empty" role="note"><span class="label na">Nothing to show</span><p>Select a different agent from the registry.</p></div>`);
            $("loadMore")?.setAttribute("hidden", "");
            return;
        }
        const a = data.agent || data;
        const name = a.name || "Agent";
        const addr = a.wallet_address || "";
        if (chip) chip.textContent = name.length > 24 ? `${name.slice(0, 22)}…` : name;
        body.innerHTML = `
            <dl class="kv dashboard-card__grid">
                <dt>Agent</dt>
                <dd class="na mono">${esc(name)}</dd>
                <dt>Agent&nbsp;ID</dt>
                <dd class="mono act-addr">${esc(a.agent_id || "")}</dd>
                <dt>Wallet</dt>
                <dd class="mono ac-addr" title="public address only">${esc(addr || "not provisioned")}</dd>
                <dt>Created</dt>
                <dd class="neutral">${esc(fmtTs(a.created_at))}</dd>
            </dl>
            <p class="field-hint">Owner-only view — activity is filtered server-side to this agent's replay ledger.</p>`;
        // show the filter lane now that a real agent is in context
        $("filterCard").removeAttribute("hidden");
    }

    // ---------------------------------------------------------------------
    // WIRING + INIT
    // ---------------------------------------------------------------------

    function wireLoadMore() {
        const btn = $("loadMoreBtn");
        let inFlight = false;
        btn?.addEventListener("click", async () => {
            if (inFlight) return; // no concurrent duplicate cursor requests
            inFlight = true;
            btn.disabled = true;
            btn.textContent = "Loading…";
            try {
                await loadPage(true);
            } finally {
                inFlight = false;
                btn.disabled = false;
                btn.innerHTML = "Load&nbsp;more";
            }
        });
    }

    function wireForm() {
        $("filterForm")?.addEventListener("submit", (e) => {
            e.preventDefault();
            applyFiltersWithValidation();
        });
        $("resetFilters")?.addEventListener("click", doReset);
    }

    async function init() {
        agentId = agentIdFromQuery();
        const githubLogin = document.querySelector(".github-login");
        const me = await AgentPayAuth.fetchMe();
        const authed = AgentPayAuth.renderLoginButton(githubLogin, me);

        wireLoadMore();
        wireForm();

        await renderContext(authed);
        if (authed) {
            await start(true);
        } else {
            // logged out: settle every lane to the gated state — a spinner
            // after a 401 would claim a feed that never loads
            renderGated();
            setPageStatus("activityState", "status--warn", "Not signed in");
            renderCount("Not signed in");
        }
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }

    return { init };
})();