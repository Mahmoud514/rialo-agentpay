/*
 * PHASE 7D.2 — PUBLIC TRANSACTION VERIFIER (frontend).
 *
 * Consumes EXACTLY ONE endpoint (public, read-only, no identity of any
 * kind — the page deliberately sends nothing and demands nothing):
 *   GET /api/public/verify?signature={sig}
 *     -> 200  { success:true, verification:{
 *                signature, status:"verified"|"no_status", executed,
 *                error, slot, block_height, block_time, fee,
 *                payer, recipient, amount_kelvin } }
 *     -> 400  { success:false, error:{ code:"VERIFY_REQUEST_INVALID", message } }
 *     -> 503  { success:false, error:{ code:"RPC_UNAVAILABLE", message } }
 *
 * PUBLIC BY DESIGN: no session, no X-Agent-Credential, no dev-login —
 * the endpoint answers without any of them, and this page never asks.
 *
 * Field whitelist (rendered verbatim from the DTO — nothing else):
 *   signature, executed/status, payer, recipient, amount_kelvin, slot,
 *   block_height, block_time, fee
 * Never rendered: owner ids, credentials, fingerprints, wallet material,
 * raw RPC bodies, filesystem paths. `verification.error` is the only
 * free-form value and is always HTML-escaped.
 *
 * No mock data: every value rendered comes from this one API response.
 * Failure is fail-closed: a 400 shows the typed reason, a 503 shows
 * "retry in a moment", any other/unparseable outcome shows an honest
 * error state. A transport-level reject (offline) also lands in the
 * error state — the top-level .catch below is the last line so the page
 * can never hang in the loading state.
 */

const githubLogin = document.querySelector(".github-login");

/* The verifier itself is public, but the shared navbar must still reflect
 * an existing GitHub session. Rendering the chip here does NOT gate the
 * verification lookup and never clears the session. */
async function hydrateNavAuth() {
    if (!githubLogin || typeof AgentPayAuth === "undefined") return;
    try {
        const me = await AgentPayAuth.fetchMe();
        AgentPayAuth.renderLoginButton(githubLogin, me);
    } catch (error) {
        console.error("Failed to load navbar auth state:", error);
        AgentPayAuth.renderLoginButton(githubLogin, null);
    }
}

/* ------------------------------------------------------------------ *
 * State pill + inline hint (dashboard vocabulary, shared classes)
 * ------------------------------------------------------------------ */

function setStatePill(kind, label) {
    const el = document.getElementById("verifyState");
    if (!el) return;
    el.className = "status " + kind;
    const text = el.querySelector(".status__label");
    if (text) text.textContent = label;
}

function setHint(text) {
    const el = document.getElementById("verifyHint");
    if (el) el.textContent = text || "";
}

/* Copy the complete signature, never a display-abbreviated form. The
 * clipboard API is used only on a secure page; the fallback keeps the
 * public verifier usable on plain-http local previews. */
function copySignature(value) {
    const text = value === null || value === undefined ? "" : String(value);
    if (!text) return;
    const done = () => setHint("Signature copied to clipboard.");
    const fallback = () => {
        const area = document.createElement("textarea");
        area.value = text;
        area.setAttribute("readonly", "");
        area.style.position = "fixed";
        area.style.opacity = "0";
        document.body.appendChild(area);
        area.select();
        try {
            document.execCommand("copy");
            done();
        } catch (_) {
            setHint("Copy unavailable — select the signature manually.");
        } finally {
            area.remove();
        }
    };
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(done, fallback);
    } else {
        fallback();
    }
}

const esc = (v) => (AgentPayAuth && AgentPayAuth.escapeHtml ? AgentPayAuth.escapeHtml(v) : String(v ?? ""));

/* ------------------------------------------------------------------ *
 * Formatting helpers (display-only; pure functions of API values)
 * ------------------------------------------------------------------ */

/* kelvin -> integer display string (kelvin is the exact unit; the raw
 * figure is the headline, the RLO ratio is the sub-line). */
function formatKelvin(value) {
    if (value === null || value === undefined) return null;
    const n = Number(value);
    if (!Number.isFinite(n)) return null;
    return n.toLocaleString("en-US", { maximumFractionDigits: 0 });
}

/* Non-amount integers (slot, height, fee) use the same grouped style. */
function formatInteger(value) {
    if (value === null || value === undefined) return null;
    const n = Number(value);
    if (!Number.isFinite(n)) return null;
    return n.toLocaleString("en-US", { maximumFractionDigits: 0 });
}

/* kelvin -> RLO display (RLO = kelvin / 1e9, same ratio the backend uses). */
function formatRloFromKelvin(value) {
    if (value === null || value === undefined) return null;
    const n = Number(value) / 1e9;
    if (!Number.isFinite(n)) return null;
    return n.toLocaleString("en-US", { maximumFractionDigits: 9 });
}

/* POSIX-seconds timestamp -> explicit UTC display. Chain time is never
 * presented as a local wall clock without saying which clock it is;
 * null stays an honest em dash. */
function formatTime(posix) {
    if (posix === null || posix === undefined) return { text: "—", title: "" };
    const ms = Number(posix) * 1000;
    const date = new Date(ms);
    if (Number.isNaN(date.getTime())) return { text: "—", title: "" };
    const stamp = date.toISOString().replace("T", " ").slice(0, 19);
    return { text: `${stamp} UTC`, title: "Block time reported by the chain (UTC)" };
}

/* ------------------------------------------------------------------ *
 * Result renderers (id: #verifyBody) — ONE renderer per canonical
 * outcome; the DTO is consumed field-by-field, nothing invented.
 * ------------------------------------------------------------------ */

function kvRow(label, cellHtml) {
    return `
            <dt>${label}</dt>
            <dd>${cellHtml}</dd>`;
}

function cell(value, extraClass) {
    const cls = extraClass ? ` class="verify-cell${extraClass}"` : "";
    const html = value === null || value === undefined ? "—" : esc(value);
    return `<span${cls}>${html}</span>`;
}

/* VERIFIED: 200 with a full canonical record. executed=true -> ok tone;
 * a verified-but-failed on-chain transaction keeps the "verified"
 * status (the record EXISTS) but is rendered warn with the node's own
 * error string (the `error` DTO field, escaped). */
function renderVerified(v) {
    const executed = v.executed === true;
    const tone = executed ? "status--on" : "status--warn";
    const badge = executed ? "verify-badge--ok" : "verify-badge--bad";
    const badgeText = executed ? "verified · executed" : "verified · failed on-chain";

    const signature = cell(v.signature, " verify-cell--break");
    const executedCell = executed
        ? `<span class="verify-cell verify-cell--ok">true</span>`
        : `<span class="verify-cell verify-cell--bad">false</span>`;
    const nodeErr = executed
        ? ""
        : v.error
            ? `<p class="verify-node-error">${esc(v.error)}</p>`
            : "";
    const amount = formatKelvin(v.amount_kelvin);
    const rlo = formatRloFromKelvin(v.amount_kelvin);
    const time = formatTime(v.block_time);
    const slot = formatInteger(v.slot);
    const height = formatInteger(v.block_height);
    const fee = formatInteger(v.fee);
    const amountMain = rlo === null ? "—" : `${esc(rlo)} <span class="verify-unit">RLO</span>`;
    const amountSub = amount === null ? "—" : `${esc(amount)} kelvin`;

    setStatePill(tone, `Verify — ${executed ? "verified" : "verified (failed on-chain)"}`);
    setHint("");

    const body = document.getElementById("verifyBody");
    if (!body) return;
    body.innerHTML = `
        <div class="verify-verdict" role="status">
            <span class="verify-badge ${badge}">${badgeText}</span>
            <span class="verify-verdict__note">The Rialo Testnet node reports this transaction.</span>
        </div>
        ${nodeErr}
        <div class="verify-summary" aria-label="Transaction summary">
            <div class="verify-summary__item verify-summary__item--amount">
                <span class="verify-summary__label">Amount</span>
                <strong class="verify-summary__value">${amountMain}</strong>
                <span class="verify-summary__meta">${amountSub}</span>
            </div>
            <div class="verify-summary__item">
                <span class="verify-summary__label">Execution</span>
                <strong class="verify-summary__value verify-summary__value--${executed ? "ok" : "bad"}">${executed ? "executed" : "not executed"}</strong>
                <span class="verify-summary__meta">${v.error ? esc(v.error) : "No on-chain error"}</span>
            </div>
            <div class="verify-summary__item">
                <span class="verify-summary__label">Block</span>
                <strong class="verify-summary__value">${height === null ? "—" : esc(height)}</strong>
                <span class="verify-summary__meta">slot ${slot === null ? "—" : esc(slot)}</span>
            </div>
        </div>
        <div class="verify-detail-head">
            <span class="verify-detail-head__title">Transaction details</span>
            <span class="verify-detail-head__status mono">${esc(v.status)}</span>
        </div>
        <dl class="kv verify-kv">
            ${kvRow("Signature", `<span class="verify-signature">${signature}<button type="button" class="verify-copy" id="copySignature" aria-label="Copy full transaction signature">Copy</button></span>`)}
            ${kvRow("Status", `<span class="verify-cell verify-cell--neutral">${esc(v.status)}</span>`)}
            ${kvRow("Executed", executedCell)}
            ${kvRow("Slot", cell(slot))}
            ${kvRow("Block&nbsp;Height", cell(height))}
            ${kvRow("Block&nbsp;Time", time.title
                ? `<span class="verify-cell verify-cell--time" title="${esc(time.title)}">${esc(time.text)}</span>`
                : cell(null))}
            ${kvRow("Fee&nbsp;(Kelvin)", cell(fee))}
            ${kvRow("Payer", cell(v.payer, " verify-cell--break"))}
            ${kvRow("Recipient", cell(v.recipient, " verify-cell--break"))}
            ${kvRow("Amount&nbsp;(Kelvin)", cell(amount))}
        </dl>`;

    document.getElementById("copySignature")?.addEventListener("click", () => {
        copySignature(v.signature);
    });
}

/* NO_STATUS: 200 with the canonical no_status record — the node
 * answered but does not know this signature yet. Temporary, retryable;
 * never a 404, never an absence verdict. All chain facts stay "—". */
function renderNoStatus(v) {
    setStatePill("status--warn", "Verify — no status yet");
    setHint("");
    const body = document.getElementById("verifyBody");
    if (!body) return;
    body.innerHTML = `
        <div class="verify-verdict" role="status">
            <span class="verify-badge verify-badge--warn">no_status</span>
            <span class="verify-verdict__note">The node answered and has no status for this signature yet — check again in a moment.</span>
        </div>
        <dl class="kv verify-kv">
            ${kvRow("Signature", cell(v.signature, " verify-cell--break"))}
            ${kvRow("Status", `<span class="verify-cell verify-cell--neutral">${esc(v.status)}</span>`)}
            ${kvRow("Executed", cell(v.executed))}
            ${kvRow("Slot", cell(v.slot))}
            ${kvRow("Block&nbsp;Height", cell(v.block_height))}
            ${kvRow("Block&nbsp;Time", cell(v.block_time))}
            ${kvRow("Fee&nbsp;(Kelvin)", cell(v.fee))}
            ${kvRow("Payer", cell(v.payer))}
            ${kvRow("Recipient", cell(v.recipient))}
            ${kvRow("Amount&nbsp;(Kelvin)", cell(v.amount_kelvin))}
        </dl>`;
}

/* INVALID: typed 400 — the request was rejected BEFORE the chain was
 * consulted. The static server reason is shown; the bad input itself is
 * never echoed by the server and is not echoed here. */
function renderInvalid(message) {
    setStatePill("status--off", "Verify — invalid signature");
    setHint("");
    const body = document.getElementById("verifyBody");
    if (!body) return;
    body.innerHTML = `
        <div class="verify-verdict" role="alert">
            <span class="verify-badge verify-badge--bad">invalid input</span>
            <span class="verify-verdict__note">${esc(message || "The signature was rejected before the chain was consulted.")}</span>
        </div>`;
}

/* RPC-UNAVAILABLE: 503 — the chain or its node did not give a decisive
 * answer. Fail closed: retry in a moment; nothing is ever rendered as
 * a verdict. */
function renderRpcUnavailable(message) {
    setStatePill("status--off", "Verify — chain unavailable");
    setHint("");
    const body = document.getElementById("verifyBody");
    if (!body) return;
    body.innerHTML = `
        <div class="dash-empty" role="alert">
            <span class="label na">Chain unavailable</span>
            <p>${esc(message || "The Rialo Testnet node could not be reached or did not give a decisive answer.")} A verdict is never guessed — retry in a moment.</p>
            <div class="lb-error-actions">
                <button type="button" class="wallet-btn wallet-btn--solid" id="verifyRetry">Retry&nbsp;↻</button>
            </div>
        </div>`;
    document.getElementById("verifyRetry")?.addEventListener("click", runLastLookup);
}

/* ERROR: any other non-2xx (or a 2xx with a malformed body) — honest
 * failure state, fail-closed, with the static server message when one
 * was supplied. */
function renderError(fallbackCode, message) {
    setStatePill("status--off", "Verify — error");
    setHint("");
    const code = fallbackCode || "ERROR";
    const body = document.getElementById("verifyBody");
    if (!body) return;
    body.innerHTML = `
        <div class="dash-empty" role="alert">
            <span class="label na">Verification failed</span>
            <p>${esc(message || "The verify endpoint returned an unexpected error.")}</p>
            <div class="lb-error-actions">
                <button type="button" class="wallet-btn wallet-btn--solid" id="verifyRetry">Retry&nbsp;↻</button>
            </div>
            <span class="field-hint lb-error-code mono">${esc(code)}</span>
        </div>`;
    document.getElementById("verifyRetry")?.addEventListener("click", runLastLookup);
}

/* LOADING: the in-flight state (restored before every attempt so a
 * retry can never leave a stale verdict on screen). */
function renderLoading(signature) {
    setStatePill("status--na", "Verify — querying chain");
    setHint(signature ? `Reading ${esc(signature.slice(0, 12))}…` : "");
    const body = document.getElementById("verifyBody");
    if (!body) return;
    body.innerHTML = `
        <div class="dash-empty" role="status">
            <span class="label na">Querying…</span>
            <p>Asking the Rialo Testnet node about this signature.</p>
        </div>`;
}

/* ------------------------------------------------------------------ *
 * Network (single endpoint, GET only — no POST/PUT/DELETE ever fires
 * from this page; nothing is submitted, signed, or mutated).
 * ------------------------------------------------------------------ */

let lastSignature = null;

async function fetchVerify(signature) {
    try {
        const response = await fetch(`/api/public/verify?signature=${encodeURIComponent(signature)}`, {
            method: "GET",
            cache: "no-store",
        });
        const payload = await response.json().catch(() => null);
        return { status: response.status, ok: response.ok, payload };
    } catch (error) {
        // network failure (offline, DNS, proxy 502 without JSON body)
        console.error("Failed to verify transaction:", error);
        return { status: 0, ok: false, payload: null };
    }
}

async function runLookup(signature) {
    lastSignature = signature;
    renderLoading(signature);

    const { status, ok, payload } = await fetchVerify(signature);

    if (status === 400) {
        renderInvalid(payload?.error?.message);
        return;
    }
    if (status === 503) {
        renderRpcUnavailable(payload?.error?.message);
        return;
    }
    if (!ok) {
        const code = payload?.error?.code || (status === 0 ? "NETWORK_UNREACHABLE" : `HTTP_${status}`);
        renderError(code, payload?.error?.message);
        return;
    }

    // 200 but the body must be the canonical shape (fail closed on a
    // malformed DTO: a half-shaped verdict is worse than an error).
    const v = payload?.verification;
    if (payload?.success !== true || !v || typeof v !== "object") {
        renderError("MALFORMED_RESPONSE");
        return;
    }
    if (v.status === "no_status") {
        renderNoStatus(v);
        return;
    }
    if (v.status === "verified") {
        renderVerified(v);
        return;
    }
    // unknown status token from a future server: never render it as a
    // known outcome.
    renderError("UNKNOWN_STATUS");
}

function runLastLookup() {
    if (!lastSignature) return;
    runLookup(lastSignature).catch(() => renderError("NETWORK_UNREACHABLE"));
}

/* Read the current input; empty -> honest hint, never a request. The
 * backend is the authority on what is valid (length/shape); the form
 * only rejects empty/whitespace client-side to avoid a pointless
 * round-trip. */
function currentSignature() {
    const input = document.getElementById("sigInput");
    const value = input ? input.value : "";
    return value.trim();
}

document.getElementById("verifyForm")?.addEventListener("submit", (event) => {
    event.preventDefault();
    const signature = currentSignature();
    if (!signature) {
        setHint("Paste a signature first — the verifier sends nothing else.");
        return;
    }
    setHint("");
    runLookup(signature).catch(() => renderError("NETWORK_UNREACHABLE"));
});

/* Deep-link support: ?signature=… pre-fills the input and runs the
 * lookup on load (the board/activity deep-link pattern). */
function boot() {
    hydrateNavAuth();
    const params = new URLSearchParams(location.search);
    const prefill = (params.get("signature") || "").trim();
    const input = document.getElementById("sigInput");
    if (input && prefill) input.value = prefill;
    if (prefill) {
        runLookup(prefill).catch(() => renderError("NETWORK_UNREACHABLE"));
    }
}

/* Top-level catch: a transport reject must settle into the error state
 * — the page may never hang in the loading state. */
boot();