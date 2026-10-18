/*
 * Agents page (Phase 5 Step 9): owner-scoped agent registry UI.
 *
 * Data sources:
 *   GET  /api/agents                  list (owner-filtered server-side)
 *   POST /api/agents                  create draft + independent wallet
 *   PATCH /api/agents/{id}            rename
 *   GET   /api/agents/{id}/balance    live chain balance (tri-state honest)
 *   PATCH /api/agents/{id}/status     lifecycle (known edge table; server
 *                                     remains the authority on edges)
 *   GET   /api/agents/{id}/policy     policy view (kelvin + derived RLO)
 *   PATCH /api/agents/{id}/policy     policy edit (RLO input; full
 *                                     replacement; unset/empty = DENIED)
 *
 * Explicitly OUT of scope here: any execution endpoint. This file performs
 * NO money-moving request of any kind — payment execution is a separate,
 * later, explicitly approved scope.
 *
 * Honesty rules (Phase 4 audit, unchanged):
 *   - unavailable data renders as an explicit empty/error state, never a
 *     simulated number;
 *   - never render filesystem paths or key material (the APIs do not
 *     return them; we still only ever touch the documented public fields);
 *   - ownership is a server concept — this page only ever sees the
 *     caller's own agents and never assumes anything about others.
 *
 * Auth/nav/chip belong to AgentPayAuth + AgentPayNav — not duplicated here.
 */

const AgentDashboard = (() => {
    const $ = (id) => document.getElementById(id);
    const esc = AgentPayAuth.escapeHtml;

    const KELVIN_PER_RLO = 1_000_000_000;

    const STATUS_TONE = {
        active: "status--on",
        draft: "status--na",
        paused: "status--warn",
        disabled: "status--off",
    };

    /* The known lifecycle edge table (mirrors the server state machine so
       invalid transitions are never offered; the SERVER stays authoritative
       and answers AGENT_INVALID_TRANSITION on any race). `disabled` is
       terminal: no outgoing edges. */
    const EDGES = {
        draft: [["active", "Activate"]],
        active: [["paused", "Pause"], ["disabled", "Disable"]],
        paused: [["active", "Resume"], ["disabled", "Disable"]],
        disabled: [],
    };

    const STATUS_LABEL = {
        draft: "Draft",
        active: "Active",
        paused: "Paused",
        disabled: "Disabled",
    };

    async function api(method, path, body) {
        try {
            const response = await fetch(path, {
                method,
                credentials: "same-origin",
                cache: "no-store",
                headers: body !== undefined ? { "Content-Type": "application/json" } : {},
                body: body !== undefined ? JSON.stringify(body) : undefined,
            });
            const data = await response.json().catch(() => null);
            return { status: response.status, data };
        } catch (error) {
            console.error(`${method} ${path} failed:`, error);
            return { status: 0, data: null };
        }
    }

    function fmtTs(unix) {
        if (!Number.isFinite(unix)) return "—";
        return new Date(unix * 1000).toLocaleString("en-GB", {
            year: "numeric", month: "short", day: "2-digit",
            hour: "2-digit", minute: "2-digit", timeZone: "UTC",
        }) + " UTC";
    }

    function fmtRloFromKelvin(kelvin) {
        if (!Number.isFinite(kelvin)) return "—";
        const rlo = kelvin / KELVIN_PER_RLO;
        return `${rlo.toLocaleString("en-US", { maximumFractionDigits: 9 })} RLO`;
    }

    const validName = (raw) => {
        const name = (raw || "").trim();
        return name.length >= 1 && name.length <= 64 && !/[\u0000-\u001f\u007f]/.test(name);
    };

    const validRecipient = (addr) => /^[A-Za-z0-9]{32,44}$/.test(addr);

    // -----------------------------------------------------------------------
    // AGENT LIST
    // -----------------------------------------------------------------------

    function lifecycleButtons(agent) {
        const edges = EDGES[agent.status] || [];
        if (edges.length === 0) {
            return `<span class="field-hint">No lifecycle actions — status is terminal.</span>`;
        }
        return edges.map(([to, label]) =>
            `<button type="button" class="wallet-btn${to === "disabled" ? " agents-btn-danger" : ""}" ` +
            `data-act="status" data-id="${esc(agent.agent_id)}" data-to="${to}">${label}</button>`
        ).join("\n");
    }

    function agentCard(agent) {
        const address = agent.wallet_address || "";
        return `
        <article class="agents-card" data-agent="${esc(agent.agent_id)}">
            <div class="panel-head dashboard-card__header">
                <h3 class="agents-name" id="nm-${esc(agent.agent_id)}">${esc(agent.name)}</h3>
                <div class="panel-head__meta dashboard-card__meta">
                    <span class="status ${STATUS_TONE[agent.status] || "status--na"}">
                        <span class="status__dot" aria-hidden="true"></span>
                        <span class="status__label">${esc(STATUS_LABEL[agent.status] || agent.status)}</span>
                    </span>
                </div>
            </div>

            <dl class="kv dashboard-card__grid">
                <dt>Agent&nbsp;ID</dt>
                <dd class="na mono">${esc(agent.agent_id)}</dd>
                <dt>Wallet</dt>
                <dd class="mono agents-addr" title="public address only">${esc(address || "not provisioned")}</dd>
                <dt>Balance</dt>
                <dd class="na" id="bal-${esc(agent.agent_id)}">loading…</dd>
                <dt>Created</dt>
                <dd class="neutral">${esc(fmtTs(agent.created_at))}</dd>
                <dt>Updated</dt>
                <dd class="neutral">${esc(fmtTs(agent.updated_at))}</dd>
            </dl>

            <div class="agents-actions">
                <button type="button" class="wallet-btn" data-act="rename" data-id="${esc(agent.agent_id)}">Rename</button>
                <button type="button" class="wallet-btn" data-act="activity" data-id="${esc(agent.agent_id)}" aria-label="View payment activity for this agent">View&nbsp;Activity</button>
                ${lifecycleButtons(agent)}
                <button type="button" class="wallet-btn" data-act="policy" data-id="${esc(agent.agent_id)}">Policy</button>
                <button type="button" class="wallet-btn wallet-btn--danger" data-act="delete" data-id="${esc(agent.agent_id)}">Delete</button>
            </div>
            <p class="agents-msg" id="msg-${esc(agent.agent_id)}" role="status"></p>

            <div class="agents-policy" id="pol-${esc(agent.agent_id)}" hidden></div>
        </article>`;
    }

    function renderList(agents, { loggedIn }) {
        const mount = $("agentList");
        const count = $("listCount");
        if (!mount) return;

        if (!loggedIn) {
            mount.innerHTML = `
                <div class="gated-note">
                    <span class="badge">Auth&nbsp;required</span>
                    <span>Sign in with GitHub to view and manage your agents.</span>
                    <a class="wallet-btn wallet-btn--solid" href="/auth/github">Login&nbsp;with&nbsp;GitHub<span>↗</span></a>
                </div>`;
            if (count) count.innerHTML = `<span class="status__label">Not signed in</span>`;
            $("createCard")?.setAttribute("hidden", "");
            return;
        }

        if (count) {
            count.className = "status status--on";
            count.innerHTML = `<span class="status__dot" aria-hidden="true"></span><span class="status__label">${agents.length} agent${agents.length === 1 ? "" : "s"}</span>`;
        }

        /* logged-in: the create lane is always usable (a zero-agent list
           must still offer the create form the empty state points to) */
        $("createCard")?.removeAttribute("hidden");

        if (!Array.isArray(agents) || agents.length === 0) {
            mount.innerHTML = `
                <div class="dash-empty" role="note">
                    <span class="label na">Empty registry</span>
                    <p>You have no agents yet. Create one above — it starts as a draft with its own independent wallet, and nothing happens until you activate it and configure a policy.</p>
                </div>`;
            return;
        }

        mount.innerHTML = agents.map(agentCard).join("\n");
        agents.forEach((agent) => {
            fillBalance(agent.agent_id);
        });
    }

    function renderListError(message) {
        const mount = $("agentList");
        const count = $("listCount");
        if (count) {
            count.className = "status status--off";
            count.innerHTML = `<span class="status__dot" aria-hidden="true"></span><span class="status__label">Registry unavailable</span>`;
        }
        if (mount) {
            mount.innerHTML = `
                <div class="dash-empty" role="note">
                    <span class="label na">Error</span>
                    <p>${esc(message)}</p>
                </div>`;
        }
    }

    // -----------------------------------------------------------------------
    // BALANCE (tri-state, honest)
    // -----------------------------------------------------------------------

    async function fillBalance(agentId) {
        const el = $(`bal-${agentId}`);
        if (!el) return;
        const { status, data } = await api("GET", `/api/agents/${encodeURIComponent(agentId)}/balance`);
        if (status !== 200 || !data || !data.success) {
            el.textContent = "unavailable";
            el.className = "bad";
            return;
        }
        if (data.balance_status === "ok") {
            el.textContent = data.balance;
            el.className = "ok";
        } else if (data.balance_status === "no_wallet") {
            el.textContent = "no wallet provisioned";
            el.className = "neutral";
        } else {
            const code = data.balance_error?.code || "error";
            el.textContent = `unavailable (${code})`;
            el.className = "bad";
        }
    }

    // -----------------------------------------------------------------------
    // CREATE
    // -----------------------------------------------------------------------

    function setMsg(elId, text, tone) {
        const el = $(elId);
        if (!el) return;
        el.textContent = text || "";
        el.className = `agents-msg${tone ? ` ${tone}` : ""}`;
    }

    async function wireCreate() {
        const form = $("createForm");
        if (!form) return;
        form.addEventListener("submit", async (event) => {
            event.preventDefault();
            const name = $("agentName")?.value || "";
            if (!validName(name)) {
                setMsg("createMsg", "Name must be 1–64 characters (no control characters).", "bad");
                return;
            }
            const btn = $("createBtn");
            btn.disabled = true;
            btn.innerHTML = "Creating...";
            const { status, data } = await api("POST", "/api/agents", { name: name.trim() });
            btn.disabled = false;
            btn.innerHTML = `Create&nbsp;Agent<span>→</span>`;
            if (status !== 201 || !data?.success) {
                setMsg("createMsg", AgentPayAuth.apiErrorMessage(data, "Agent creation failed"), "bad");
                return;
            }
            setMsg("createMsg", `Agent "${data.agent.name}" created (draft).`, "ok");
            form.reset();
            await load(true);
        });
    }

    // -----------------------------------------------------------------------
    // RENAME / LIFECYCLE / POLICY  (event delegation on the list)
    // -----------------------------------------------------------------------

    function beginRename(agentId) {
        const heading = $(`nm-${agentId}`);
        if (!heading || heading.querySelector("input")) return;
        const current = heading.textContent;
        heading.innerHTML = `
            <span class="agents-rename-row">
                <input class="agents-input" id="rn-${agentId}" type="text" maxlength="64" value="${esc(current)}">
                <button type="button" class="wallet-btn wallet-btn--solid" data-act="rename-save" data-id="${esc(agentId)}">Save</button>
                <button type="button" class="wallet-btn" data-act="rename-cancel" data-id="${esc(agentId)}">Cancel</button>
            </span>`;
        $("rn-" + agentId)?.focus();
    }

    async function saveRename(agentId) {
        const input = $(`rn-${agentId}`);
        const name = input?.value || "";
        if (!validName(name)) {
            setMsg(`msg-${agentId}`, "Name must be 1–64 characters.", "bad");
            return;
        }
        const { status, data } = await api("PATCH", `/api/agents/${encodeURIComponent(agentId)}`, { name: name.trim() });
        if (status !== 200 || !data?.success) {
            setMsg(`msg-${agentId}`, AgentPayAuth.apiErrorMessage(data, "Rename failed"), "bad");
            return;
        }
        await load(true); // refresh from server — never patch the local model
    }

    async function changeStatus(agentId, to) {
        if (to === "disabled") {
            const ok = window.confirm(
                "Disable this agent?\n\nDisabled is TERMINAL: no lifecycle action can bring it back, and every future action will be denied.");
            if (!ok) return;
        }
        const { status, data } = await api("PATCH", `/api/agents/${encodeURIComponent(agentId)}/status`, { status: to });
        if (status !== 200 || !data?.success) {
            setMsg(`msg-${agentId}`, AgentPayAuth.apiErrorMessage(data, "Status change failed"), "bad");
            return;
        }
        await load(true);
    }

    async function deleteAgent(agentId) {
        const ok = window.confirm(
            "Delete this agent permanently?\n\nThis removes the agent record and CANNOT be undone. " +
            "The agent's wallet and signer registration must be cleaned up separately.");
        if (!ok) return;
        
        const { status, data } = await api("DELETE", `/api/agents/${encodeURIComponent(agentId)}`);
        if (status !== 200 && status !== 204) {
            setMsg(`msg-${agentId}`, AgentPayAuth.apiErrorMessage(data, "Delete failed — endpoint may not be implemented"), "bad");
            return;
        }
        // Remove the card from DOM immediately for responsive UI
        const card = document.querySelector(`[data-agent="${CSS.escape(agentId)}"]`);
        if (card) card.remove();
        // Refresh list count
        const remaining = document.querySelectorAll('.agents-card').length;
        const count = $("listCount");
        if (count) {
            count.innerHTML = `<span class="status__label">${remaining} agent${remaining === 1 ? "" : "s"}</span>`;
        }
        await load(true);
    }

    function policyHtml(agentId, body) {
        const p = body?.policy || {};
        const configured = Boolean(body?.configured);
        const kelvin = (k) => (Number.isFinite(k) ? k : null);
        const ptxK = kelvin(p.max_payment_per_tx_kelvin);
        const dayK = kelvin(p.daily_payment_limit_kelvin);
        const ptxVal = ptxK === null ? "" : String(ptxK / KELVIN_PER_RLO);
        const dayVal = dayK === null ? "" : String(dayK / KELVIN_PER_RLO);
        const limit = (k) => k === null
            ? `<span class="bad">unset — denied</span>`
            : `<span class="ok mono">${k} K · ${esc(fmtRloFromKelvin(k))}</span>`;
        const list = (items) => Array.isArray(items) && items.length
            ? `<span class="mono agents-list">${items.map(esc).join("<br>")}</span>`
            : `<span class="bad">none — denied</span>`;
        return `
            <div class="panel-head dashboard-card__header">
                <span class="label">Payment&nbsp;Policy</span>
                <div class="panel-head__meta dashboard-card__meta">
                    <span class="badge${configured ? " badge--cyan" : ""}">${configured ? "configured" : "not configured — everything is denied"}</span>
                </div>
            </div>
            <dl class="kv dashboard-card__grid">
                <dt>Max&nbsp;per&nbsp;transaction</dt>
                <dd>${limit(ptxK)}</dd>
                <dt>Daily&nbsp;limit</dt>
                <dd>${limit(dayK)}</dd>
                <dt>Allowed&nbsp;recipients</dt>
                <dd>${list(p.allowed_recipients)}</dd>
                <dt>Allowed&nbsp;actions</dt>
                <dd>${list(p.allowed_actions)}</dd>
            </dl>
            <p class="field-hint">Deny-by-default: an unset limit or an empty list means DENIED — never unlimited. Editing replaces the whole policy; leave a limit empty to explicitly un-set it (it will deny).</p>
            <form class="agents-form" id="pf-${agentId}" autocomplete="off">
                <div class="agents-policy-edit">
                    <label class="field-label" for="ptx-${agentId}">Max per tx (RLO, empty = unset/deny)</label>
                    <input class="agents-input" id="ptx-${agentId}" type="text" inputmode="decimal" value="${esc(ptxVal)}">
                    <label class="field-label" for="pday-${agentId}">Daily limit (RLO, empty = unset/deny)</label>
                    <input class="agents-input" id="pday-${agentId}" type="text" inputmode="decimal" value="${esc(dayVal)}">
                    <label class="field-label" for="precip-${agentId}">Allowed recipients (one address per line)</label>
                    <textarea class="agents-input agents-textarea" id="precip-${agentId}" rows="2"
                              placeholder="32–44 alphanumeric addresses">${(p.allowed_recipients || []).map(esc).join("\n")}</textarea>
                    <label class="agents-check"><input type="checkbox" id="pact-${agentId}"
                           ${(p.allowed_actions || []).includes("payment") ? "checked" : ""}> allow “payment” action</label>
                </div>
                <div class="agents-actions">
                    <button type="submit" class="wallet-btn wallet-btn--solid">Save&nbsp;Policy</button>
                </div>
            </form>
            <p class="agents-msg" id="pmsg-${agentId}" role="status"></p>`;
    }

    async function togglePolicy(agentId) {
        const mount = $(`pol-${agentId}`);
        if (!mount) return;
        if (!mount.hidden) {
            mount.hidden = true;
            mount.innerHTML = "";
            return;
        }
        mount.hidden = false;
        mount.innerHTML = `<p class="field-hint">Loading policy…</p>`;
        const { status, data } = await api("GET", `/api/agents/${encodeURIComponent(agentId)}/policy`);
        if (status !== 200 || !data) {
            mount.innerHTML = `<p class="agents-msg bad">${esc(AgentPayAuth.apiErrorMessage(data, "Policy could not be loaded"))}</p>`;
            return;
        }
        mount.innerHTML = policyHtml(agentId, data);
        const daily = $(`pday-${agentId}`);
        if (daily) daily.value = Number.isFinite(data.policy?.daily_payment_limit_kelvin)
            ? String(data.policy.daily_payment_limit_kelvin / KELVIN_PER_RLO)
            : "";
        wirePolicyForm(agentId);
    }

    function parseRloField(value) {
        const t = (value || "").trim();
        if (t === "") return { unset: true };
        const n = Number(t);
        if (!Number.isFinite(n) || n <= 0) return { bad: true };
        return { rlo: n };
    }

    function wirePolicyForm(agentId) {
        const form = $(`pf-${agentId}`);
        if (!form || form.dataset.wired === "1") return;
        form.dataset.wired = "1";
        form.addEventListener("submit", async (event) => {
            event.preventDefault();
            const msg = (text, tone) => setMsg(`pmsg-${agentId}`, text, tone);

            const ptx = parseRloField($(`ptx-${agentId}`)?.value);
            const day = parseRloField($(`pday-${agentId}`)?.value);
            if (ptx.bad || day.bad) {
                msg("Limits must be positive numbers of RLO (or left empty to deny).", "bad");
                return;
            }
            const recipients = ($(`precip-${agentId}`)?.value || "")
                .split(/\s+/).map((s) => s.trim()).filter(Boolean);
            const bad = recipients.find((r) => !validRecipient(r));
            if (bad) {
                msg(`Invalid recipient: ${bad} (32–44 alphanumeric characters).`, "bad");
                return;
            }
            const allowPayment = $(`pact-${agentId}`)?.checked === true;

            const body = {
                allowed_recipients: recipients,
                allowed_actions: allowPayment ? ["payment"] : [],
            };
            if (!ptx.unset) body.max_payment_per_tx_rlo = ptx.rlo;
            if (!day.unset) body.daily_payment_limit_rlo = day.rlo;

            const { status, data } = await api("PATCH", `/api/agents/${encodeURIComponent(agentId)}/policy`, body);
            if (status !== 200 || !data) {
                msg(AgentPayAuth.apiErrorMessage(data, "Policy update failed"), "bad");
                return;
            }
            msg("Policy saved.", "ok");
            /* re-render read-back from the server response (authoritative) */
            const mount = $(`pol-${agentId}`);
            mount.innerHTML = policyHtml(agentId, data);
            const daily = $(`pday-${agentId}`);
            if (daily) daily.value = Number.isFinite(data.policy?.daily_payment_limit_kelvin)
                ? String(data.policy.daily_payment_limit_kelvin / KELVIN_PER_RLO)
                : "";
            wirePolicyForm(agentId);
        });
    }

    function wireList() {
        const mount = $("agentList");
        if (!mount || mount.dataset.wired === "1") return;
        mount.dataset.wired = "1";
        mount.addEventListener("click", async (event) => {
            const btn = event.target.closest("[data-act]");
            if (!btn) return;
            const { act, id: agentId, to } = btn.dataset;
            if (act === "rename") beginRename(agentId);
            else if (act === "rename-save") await saveRename(agentId);
            else if (act === "rename-cancel") await load(true);
            else if (act === "status") await changeStatus(agentId, to);
            else if (act === "policy") await togglePolicy(agentId);
            else if (act === "activity") {
                // dedicated owner-scoped surface: agents.html -> activity.html
                window.location.href = `/activity.html?agent=${encodeURIComponent(agentId)}`;
            }
            else if (act === "delete") await deleteAgent(agentId);
        });
    }

    // -----------------------------------------------------------------------
    // LOAD
    // -----------------------------------------------------------------------

    async function load(forceList) {
        const githubLogin = document.querySelector(".github-login");
        const me = await AgentPayAuth.fetchMe();
        const authed = AgentPayAuth.renderLoginButton(githubLogin, me);
        const reg = $("registryState");

        if (!authed) {
            if (reg) {
                reg.className = "status status--na";
                reg.innerHTML = `<span class="status__dot" aria-hidden="true"></span><span class="status__label">Registry — not signed in</span>`;
            }
            renderList([], { loggedIn: false });
            return;
        }
        if (reg) {
            reg.className = "status status--on";
            reg.innerHTML = `<span class="status__dot" aria-hidden="true"></span><span class="status__label">Signed in</span>`;
        }
        if (forceList === true || !document.querySelector(".agents-card")) {
            const { status, data } = await api("GET", "/api/agents");
            if (status !== 200 || !data || !data.success || !Array.isArray(data.agents)) {
                renderListError(AgentPayAuth.apiErrorMessage(data, "Agent registry could not be loaded"));
                return;
            }
            renderList(data.agents.slice().reverse(), { loggedIn: true });
        }
    }

    function init() {
        wireCreate();
        wireList();
        load();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }

    return { load, renderList };
})();
