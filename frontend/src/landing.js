/*
 * Landing page behavior for index.html.
 *
 * Strict data rule: every live-looking value on this page comes from a real
 * backend endpoint. There is NO fallback sample data anywhere in this file.
 *
 *   /api/health          -> agentpay status, rialo_rpc status, block_height
 *   /api/program/status  -> program on-chain status, program-payment path
 *   /api/me              -> GitHub session (shared AgentPayAuth, auth.js)
 *
 * Anything without a real source renders an honest empty state defined in
 * the HTML ("NO VERIFIED ... YET"). Sections 05/06 are static empty states —
 * no code populates them, by design.
 *
 * Modules:
 *   net      — polls real health, renders netcards
 *   auth     — session widget via AgentPayAuth, gates nav app-links
 *   motion   — scroll reveal + FAQ accordion
 */

(function () {
    "use strict";

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    const REFRESH_MS = 30000;
    const DASH = "—";

    function setText(id, value, isNa) {
        const el = document.getElementById(id);
        if (!el) return;
        el.textContent = value;
        el.classList.toggle("is-na", Boolean(isNa));
    }

    function setStatus(id, kind, text) {
        const el = document.getElementById(id);
        if (!el) return;
        render(el, kind, text);
        // mirror every element that declares data-sync="<id>"
        document.querySelectorAll('[data-sync="' + id + '"]')
            .forEach((m) => render(m, kind, text));
    }

    function render(el, kind, text) {
        el.className = "status " + kind;
        const dot = el.querySelector(".status__dot");
        if (dot) dot.remove();
        el.insertAdjacentHTML("afterbegin", '<span class="status__dot" aria-hidden="true"></span>');
        const label = el.querySelector(".status__label");
        if (label) label.textContent = text;
    }

    function fmtHeight(n) {
        return typeof n === "number" && Number.isFinite(n)
            ? n.toLocaleString("en-US")
            : DASH;
    }

    function timeLabel(d) {
        return d.toTimeString().slice(0, 8) + " local";
    }

    // ------------------------------------------------------------------
    // net — LIVE NETWORK (sections render from /api/health + program status)
    // ------------------------------------------------------------------

    const net = {
        async refreshHealth() {
            const updated = document.getElementById("netUpdated");
            try {
                const res = await fetch("/api/health", {
                    credentials: "same-origin",
                    cache: "no-store",
                });
                const data = await res.json();

                // AgentPay service
                if (data.agentpay === "ok") {
                    setStatus("stAgentpay", "status--on", "Operational");
                } else {
                    setStatus("stAgentpay", "status--off", "Degraded");
                }

                // RPC + block height — shown ONLY when the backend reports ok
                const rpcOk = data.rialo_rpc === "ok";
                setText("valBlock", rpcOk ? fmtHeight(data.block_height) : DASH, !rpcOk);

                const rpcNote = document.getElementById("netRpcNote");
                if (rpcOk) {
                    setStatus("stRpc", "status--on", "Online");
                    if (rpcNote) rpcNote.textContent = "GET /api/health · rialo_rpc: ok";
                } else if (data.rialo_rpc === "unavailable") {
                    setStatus("stRpc", "status--off", "Unavailable");
                    const code = data.error && data.error.code ? data.error.code : "RPC_UNAVAILABLE";
                    if (rpcNote) rpcNote.textContent = `GET /api/health · ${code}`;
                } else {
                    setStatus("stRpc", "status--warn", "Error");
                    if (rpcNote) rpcNote.textContent = "GET /api/health · error response";
                }

                if (updated) updated.textContent = "Last checked " + timeLabel(new Date());
            } catch (err) {
                setStatus("stRpc", "status--off", "Unreachable");
                setStatus("stAgentpay", "status--off", "Unreachable");
                setText("valBlock", DASH, true);
                if (updated) updated.textContent = "Last check failed " + timeLabel(new Date());
            }
        },

        async refreshProgram() {
            const card = document.getElementById("stProgram");
            const note = document.getElementById("netProgramNote");
            try {
                const res = await fetch("/api/program/status", {
                    credentials: "same-origin",
                    cache: "no-store",
                });
                if (!res.ok) throw new Error(String(res.status));
                const data = await res.json();

                const onChain = data.on_chain && data.on_chain.status;
                if (onChain === "deployed") {
                    setStatus("stProgram", "status--on", "Deployed");
                } else if (onChain) {
                    setStatus("stProgram", "status--warn", String(onChain));
                } else {
                    setStatus("stProgram", "status--na", "Not available");
                }

                // Honest path state: three payment paths exist with different safety postures.
                // The direct /api/payment path is always available for humans.
                // The program-mediated PDA escrow path requires an explicit operator cap.
                // Agent programmable payments via /api/agents/triggers/payments are LIVE and
                // use hardened signer + policy enforcement (distinct from the Venus PDA path).
                if (note) {
                    note.textContent = data.path_enabled
                        ? "program PDA escrow enabled · cap set by operator"
                        : "direct /api/payment live · program PDA escrow disabled · Agent policy payments live via isolated signer";
                }
            } catch (err) {
                setStatus("stProgram", "status--na", "Not available");
                if (note) note.textContent = "GET /api/program/status · no response";
                if (card) card.classList.add("is-stale");
            }
        },

        start() {
            this.refreshHealth();
            this.refreshProgram();
            setInterval(() => {
                this.refreshHealth();
                this.refreshProgram();
            }, REFRESH_MS);
        },
    };

    // ------------------------------------------------------------------
    // schema view — wire the "Schema View" badge to /api/schema
    // ------------------------------------------------------------------

    const schemaBadge = document.querySelector(".badge--cyan");
    if (schemaBadge && schemaBadge.textContent.includes("Schema")) {
        schemaBadge.style.cursor = "pointer";
        schemaBadge.title = "Click to view schema";
        schemaBadge.addEventListener("click", () => {
            window.open("/api/schema", "_blank", "noopener,noreferrer");
        });
    }

    // ------------------------------------------------------------------
    // auth — reuse AgentPayAuth (auth.js); never duplicate session logic
    // ------------------------------------------------------------------

    async function initAuth() {
        // Check for OAuth rate-limit redirect from middleware
        const urlParams = new URLSearchParams(window.location.search);
        const rateLimited = urlParams.get('rate_limited');
        const retryAfter = urlParams.get('retry_after');
        if (rateLimited === 'oauth' && retryAfter) {
            const minutes = Math.ceil(parseInt(retryAfter, 10) / 60);
            const msg = minutes > 1 
                ? `GitHub sign-in is temporarily rate limited. Please try again in ${minutes} minutes.`
                : 'GitHub sign-in is temporarily rate limited. Please try again shortly.';
            // Display rate-limit notice in the hero status area if available
            const heroMeta = document.querySelector('.hero__meta');
            if (heroMeta) {
                const notice = document.createElement('div');
                notice.className = 'status status--warn';
                notice.style.cssText = 'margin-top:12px;width:100%;';
                notice.innerHTML = `<span class="status__dot" aria-hidden="true"></span><span class="status__label">${msg}</span>`;
                heroMeta.appendChild(notice);
            }
            // Clean URL without reload
            window.history.replaceState({}, '', window.location.pathname);
        }

        const loginEl = document.querySelector(".github-login");
        if (!loginEl || typeof AgentPayAuth === "undefined") return;

        const data = await AgentPayAuth.fetchMe();
        // renderLoginButton() owns the body.is-authed class itself (auth.js) —
        // do not toggle it here.
        const isLoggedIn = AgentPayAuth.renderLoginButton(loginEl, data);

        // The landing CTA routes to the real app (agent creation and
        // management live at /agents.html once logged in).
        const launch = document.getElementById("launchApp");
        if (launch) launch.href = isLoggedIn ? "/wallet" : "/auth/github";
        const launch2 = document.getElementById("launchAgentpay");
        if (launch2) launch2.href = isLoggedIn ? "/wallet" : "/auth/github";
    }

    // ------------------------------------------------------------------
    // motion — scroll reveal + FAQ accordion (pure UI, no data)
    // ------------------------------------------------------------------

    function initReveal() {
        const items = document.querySelectorAll(".reveal");
        if (!("IntersectionObserver" in window)) {
            items.forEach((el) => el.classList.add("is-in"));
            return;
        }
        const io = new IntersectionObserver(
            (entries) => {
                entries.forEach((e) => {
                    if (e.isIntersecting) {
                        e.target.classList.add("is-in");
                        io.unobserve(e.target);
                    }
                });
            },
            { rootMargin: "0px 0px -8% 0px", threshold: 0.05 }
        );
        items.forEach((el) => io.observe(el));
    }

    function initFaq() {
        document.querySelectorAll(".faq__item").forEach((item) => {
            const btn = item.querySelector(".faq__q");
            const panel = item.querySelector(".faq__a");
            if (!btn || !panel) return;

            btn.addEventListener("click", () => {
                const open = item.dataset.open === "true";
                item.dataset.open = String(!open);
                btn.setAttribute("aria-expanded", String(!open));
                panel.style.maxHeight = open ? "0px" : panel.scrollHeight + "px";
            });
        });
    }

    // ------------------------------------------------------------------

    initReveal();
    initFaq();
    net.start();
    initAuth();
})();
