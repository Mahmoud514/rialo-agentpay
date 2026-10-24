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

/* Submission attachments: any browser-readable file is accepted; the
 * backend stores small, bounded data URLs so evidence survives restarts.
 * Images are previewed only for safe raster MIME types; every file is
 * downloaded through a Blob URL (never rendered as HTML/SVG). */
const MAX_SUBMISSION_FILES = 5;
const MAX_RAW_SUBMISSION_BYTES = 2_000_000;
const MAX_SUBMISSION_IMAGE_DIMENSION = 1400;
let PENDING_SUBMISSION_FILES = [];

function attachmentMeta(file) {
    if (typeof file === "string") {
        return { name: "Attachment", content_type: dataUrlMime(file), data_url: file };
    }
    if (file && typeof file === "object") {
        return {
            name: String(file.name || "Attachment"),
            content_type: String(file.content_type || dataUrlMime(file.data_url || "")),
            data_url: String(file.data_url || ""),
        };
    }
    return { name: "Attachment", content_type: "", data_url: "" };
}

function dataUrlMime(dataUrl) {
    const match = /^data:([^;,]+)[;,]/.exec(String(dataUrl || ""));
    return match ? match[1].toLowerCase() : "";
}

function isPreviewableImage(contentType) {
    return ["image/png", "image/jpeg", "image/jpg", "image/webp", "image/gif"]
        .includes(String(contentType || "").toLowerCase());
}

function formatBytes(bytes) {
    const n = Number(bytes);
    if (!Number.isFinite(n) || n <= 0) return "0 B";
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function readFileDataUrl(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result || ""));
        reader.onerror = () => reject(new Error(`Could not read ${file.name}`));
        reader.readAsDataURL(file);
    });
}

function compressImage(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => {
            const img = new Image();
            img.onload = () => {
                const scale = Math.min(
                    1,
                    MAX_SUBMISSION_IMAGE_DIMENSION / Math.max(img.width, img.height),
                );
                const canvas = document.createElement("canvas");
                canvas.width = Math.max(1, Math.round(img.width * scale));
                canvas.height = Math.max(1, Math.round(img.height * scale));
                const ctx = canvas.getContext("2d");
                if (!ctx) return reject(new Error(`Could not process ${file.name}`));
                ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
                const type = file.type === "image/png" ? "image/png" : "image/jpeg";
                resolve({
                    data_url: canvas.toDataURL(type, 0.82),
                    content_type: type,
                });
            };
            img.onerror = () => reject(new Error(`Could not read ${file.name}`));
            img.src = String(reader.result || "");
        };
        reader.onerror = () => reject(new Error(`Could not read ${file.name}`));
        reader.readAsDataURL(file);
    });
}

async function prepareSubmissionFile(file) {
    if (file.size > MAX_RAW_SUBMISSION_BYTES) {
        throw new Error(`${file.name} is larger than ${formatBytes(MAX_RAW_SUBMISSION_BYTES)}`);
    }
    const safeName = String(file.name || "attachment")
        .slice(0, 120)
        .replace(/[\\/]/g, "_");
    let prepared;
    if (isPreviewableImage(file.type) && file.type !== "image/gif") {
        prepared = await compressImage(file);
    } else {
        const dataUrl = await readFileDataUrl(file);
        prepared = {
            data_url: dataUrl,
            content_type: file.type || dataUrlMime(dataUrl),
        };
    }
    if (!prepared.data_url.startsWith("data:")) {
        throw new Error(`Could not prepare ${safeName}`);
    }
    return {
        name: safeName,
        content_type: prepared.content_type,
        data_url: prepared.data_url,
    };
}

function renderSubmissionPreview() {
    const box = document.getElementById("mkSubPreview");
    if (!box) return;
    if (PENDING_SUBMISSION_FILES.length === 0) {
        box.innerHTML = "";
        return;
    }
    box.innerHTML = PENDING_SUBMISSION_FILES.map((file, index) => {
        const preview = isPreviewableImage(file.content_type)
            ? `<img src="${esc(file.data_url)}" alt="${esc(file.name)}">`
            : `<span class="mk-file-icon">${esc((file.content_type.split("/")[1] || "file").slice(0, 5).toUpperCase())}</span>`;
        return `<span class="mk-file-preview">${preview}<span class="mk-file-preview__meta"><strong>${esc(file.name)}</strong><small>${esc(file.content_type || "file")}</small></span><button type="button" class="mk-file-remove" data-remove-file="${index}" aria-label="Remove ${esc(file.name)}">×</button></span>`;
    }).join("");
    box.querySelectorAll("[data-remove-file]").forEach((button) => {
        button.addEventListener("click", () => {
            const index = Number(button.getAttribute("data-remove-file"));
            PENDING_SUBMISSION_FILES.splice(index, 1);
            renderSubmissionPreview();
        });
    });
}

async function handleSubmissionFileInput(input) {
    const selected = Array.from(input.files || []);
    if (selected.length === 0) return;
    const message = document.getElementById("mkSubFileMsg");
    if (message) message.textContent = "";
    const remaining = MAX_SUBMISSION_FILES - PENDING_SUBMISSION_FILES.length;
    if (selected.length > remaining) {
        if (message) message.textContent = `You can attach at most ${MAX_SUBMISSION_FILES} files.`;
        input.value = "";
        return;
    }
    input.disabled = true;
    try {
        for (const file of selected) {
            PENDING_SUBMISSION_FILES.push(await prepareSubmissionFile(file));
        }
        renderSubmissionPreview();
    } catch (error) {
        if (message) message.textContent = error.message || String(error);
    } finally {
        input.disabled = false;
        input.value = "";
    }
}

function renderAttachments(files) {
    if (!Array.isArray(files) || files.length === 0) return "";
    return `<div class="mk-attachments">${files.map((raw, index) => {
        const file = attachmentMeta(raw);
        const image = isPreviewableImage(file.content_type)
            ? `<img class="mk-attachment__thumb" src="${esc(file.data_url)}" alt="${esc(file.name)}" loading="lazy">`
            : `<span class="mk-attachment__icon">${esc((file.content_type.split("/")[1] || "file").slice(0, 5).toUpperCase())}</span>`;
        return `<button type="button" class="mk-attachment" data-submission-file="${index}" title="Download ${esc(file.name)}">${image}<span class="mk-attachment__meta"><strong>${esc(file.name)}</strong><small>${esc(file.content_type || "file")}</small></span><span class="mk-attachment__download" aria-hidden="true">↓</span></button>`;
    }).join("")}</div>`;
}

function downloadSubmissionFile(file) {
    const meta = attachmentMeta(file);
    const comma = meta.data_url.indexOf(",");
    if (comma < 0) return;
    const metaPart = meta.data_url.slice(5, comma);
    if (!metaPart.endsWith(";base64")) return;
    try {
        const binary = atob(meta.data_url.slice(comma + 1));
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
        const blob = new Blob([bytes], { type: meta.content_type || "application/octet-stream" });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = meta.name || "attachment";
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (error) {
        console.error("Attachment download failed:", error);
    }
}

function safeHttpUrl(value) {
    const raw = String(value ?? "").trim();
    if (!raw) return null;
    try {
        const url = new URL(raw, location.origin);
        return url.protocol === "http:" || url.protocol === "https:" ? url.href : null;
    } catch {
        return null;
    }
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
let CURRENT_LOGIN = "";
let MARKETPLACE_POLL_TIMER = null;
const NOTIFIED_SUBMISSIONS = new Set();
let TOAST_TASKS = [];

function hideOwnerToast() {
    const toast = $("mkOwnerToast");
    if (!toast) return;
    toast.hidden = true;
    toast.innerHTML = "";
    TOAST_TASKS = [];
}

function showOwnerToast(tasks) {
    const toast = $("mkOwnerToast");
    if (!toast || !tasks.length) return;
    for (const task of tasks) {
        if (task && task.task_id) NOTIFIED_SUBMISSIONS.add(task.task_id);
    }
    TOAST_TASKS = tasks;
    const first = tasks[0];
    const count = tasks.length;
    toast.innerHTML = `
        <span class="mk-toast__dot" aria-hidden="true"></span>
        <div class="mk-toast__copy">
            <strong>${count === 1 ? "Work submitted for review" : `${count} tasks need review`}</strong>
            <span>${esc(first.title || "A worker submitted work")} — review the evidence before paying.</span>
        </div>
        <button type="button" class="wallet-btn wallet-btn--sm wallet-btn--solid" id="mkToastReview">Review</button>
        <button type="button" class="mk-toast__close" id="mkToastClose" aria-label="Dismiss review notification">×</button>`;
    toast.hidden = false;
    const review = document.getElementById("mkToastReview");
    if (review) {
        review.addEventListener("click", () => {
            hideOwnerToast();
            if (first.task_id) openDetail(first.task_id);
        });
    }
    const close = document.getElementById("mkToastClose");
    if (close) close.addEventListener("click", hideOwnerToast);
}

function startMarketplacePolling() {
    if (MARKETPLACE_POLL_TIMER) return;
    MARKETPLACE_POLL_TIMER = window.setInterval(() => {
        if (document.visibilityState !== "visible") return;
        // Never replace the list while the owner is typing a task. The
        // detail drawer is independent, so a silent list refresh is safe.
        const form = document.getElementById("mkCreateForm");
        if (form && form.contains(document.activeElement)) return;
        loadTasks({ silent: true }).catch((error) => {
            console.warn("Marketplace background refresh failed:", error);
        });
    }, 15000);
}

function setMarketplaceState(kind, label) {
    const el = $("mkState");
    if (!el) return;
    el.className = `status ${kind}`;
    el.innerHTML =
        `<span class="status__dot" aria-hidden="true"></span>` +
        `<span class="status__label">${esc(label)}</span>`;
}

async function loadTasks(options = {}) {
    const silent = options && options.silent === true;
    const body = $("mkBody");
    const { ok, status, data } = await api("/api/tasks/open");

    if (!ok) {
        if (silent) return;
        setMarketplaceState("status--off", "Marketplace — unavailable");
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
    const previous = new Map(LAST_LIST.map((t) => [t.task_id, statusToken(t.status)]));
    LAST_LIST = tasks;
    $("mkCount").textContent = String(tasks.length);

    if (tasks.length === 0) {
        setMarketplaceState("status--na", "Marketplace — empty");
        const createMsg = $("mkCreateMsg");
        if (createMsg) {
            createMsg.textContent = "";
            createMsg.removeAttribute("role");
        }
        body.innerHTML = `
            <div class="dash-empty" role="status">
                <span class="label na">No open tasks</span>
                <p>Nothing on the board right now. Owners: create one below${document.body.classList.contains("is-authed") ? "" : " after signing in"}.</p>
            </div>`;
        return;
    }

    setMarketplaceState("status--on", "Marketplace — live");

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

    // Owner-side, in-page notification. The API has no push channel; this
    // polling loop surfaces a worker submission as soon as the page sees it.
    const review = tasks.filter((t) => {
        if (!CURRENT_LOGIN || t.owner_name !== CURRENT_LOGIN) return false;
        if (statusToken(t.status) !== "submitted") return false;
        if (previous.get(t.task_id) === "submitted") return false;
        return !NOTIFIED_SUBMISSIONS.has(t.task_id);
    });
    if (review.length) showOwnerToast(review);
}

function resetListLoading() {
    setMarketplaceState("status--na", "Marketplace — loading");
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
    PENDING_SUBMISSION_FILES = [];
    $("detailStatus").textContent = t.status ? statusLabel(t.status) : "?";
    renderDetail(t);
}

function renderDetail(t) {
    const body = $("detailBody");
    const attachments = Array.isArray(t.submission_files) ? t.submission_files : [];
    const submissionUrl = safeHttpUrl(t.submission_url);
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
                ${t.worker_recipient ? `<span class="mk-payout">Worker payout: <code>${esc(t.worker_recipient)}</code></span>` : ""}
                <span>Created: ${esc(fmtDate(t.created_at))}</span>
                <span>Updated: ${esc(fmtDate(t.updated_at))}</span>
            </div>
            ${(submissionUrl || t.submission_notes || attachments.length)
                ? `<div class="mk-submission">
                    <span class="label">Submitted work</span>
                    ${submissionUrl ? `<p class="field-hint"><a class="dash-inline-link" href="${esc(submissionUrl)}" target="_blank" rel="noopener noreferrer">${esc(submissionUrl)}</a></p>` : ""}
                    ${t.submission_notes ? `<p class="mk-submission__notes">${esc(t.submission_notes)}</p>` : ""}
                    ${renderAttachments(attachments)}
                </div>`
                : ""}
            ${t.review_notes ? `<div><span class="label">Review notes</span><p class="field-hint">${esc(t.review_notes)}</p></div>` : ""}
            ${t.payment_tx_signature ? `<div><span class="label">Payment tx</span><p class="field-hint mono">${esc(t.payment_tx_signature)}</p></div>` : ""}
            ${t.payment_error ? `<div><span class="label">Payment error</span><p class="field-hint">${esc(t.payment_error)}</p></div>` : ""}
        </div>
        <div class="mk-actions" id="mkActionArea"></div>`;

    body.querySelectorAll("[data-submission-file]").forEach((button) => {
        button.addEventListener("click", () => {
            const index = Number(button.getAttribute("data-submission-file"));
            downloadSubmissionFile(attachments[index]);
        });
    });

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
            <div class="mk-submit-form">
                <label class="mk-sub-field mk-sub-field--wide">
                    <span class="label">Work notes</span>
                    <textarea id="mkSubNotes" class="input" rows="3" placeholder="Describe what you completed, include any handoff details…"></textarea>
                </label>
                <label class="mk-sub-field">
                    <span class="label">Proof URL <span class="mk-optional">optional</span></span>
                    <input id="mkSubUrl" class="input mono" placeholder="https://…">
                </label>
                <label class="mk-sub-field mk-sub-field--wide">
                    <span class="label">Attachments <span class="mk-optional">optional</span></span>
                    <input id="mkSubFiles" class="input mk-file-input" type="file" multiple>
                    <span class="field-hint">Up to ${MAX_SUBMISSION_FILES} files, max ${formatBytes(MAX_RAW_SUBMISSION_BYTES)} each. Images are resized; any file type is accepted.</span>
                </label>
                <div id="mkSubPreview" class="mk-sub-preview"></div>
                <p id="mkSubFileMsg" class="field-hint mk-form__status" role="status" aria-live="polite"></p>
                <button class="wallet-btn wallet-btn--sm wallet-btn--solid" id="mkSubmit">Submit work</button>
            </div>`;
        document.getElementById("mkSubFiles").addEventListener("change", (event) => {
            handleSubmissionFileInput(event.target);
        });
        document.getElementById("mkSubmit").addEventListener("click", () => act("submit"));
    }

    // Owner path
    if (d.isOwner) {
        if (st === "submitted") {
            // The owner can approve the exact worker submission or reject
            // it (both transitions are legal from Submitted after this
            // change). Rejection releases the reservation.
            area.insertAdjacentHTML("beforeend", `
                <input id="mkRevNotes" class="input" placeholder="Review notes (optional)" style="min-width:220px">
                <button class="wallet-btn wallet-btn--sm wallet-btn--solid" id="mkApprove">Approve &amp; pay</button>
                <button class="wallet-btn wallet-btn--sm wallet-btn--danger" id="mkReject">Reject</button>`);
            document.getElementById("mkApprove").addEventListener("click", () => act("review", "approve"));
            document.getElementById("mkReject").addEventListener("click", () => act("review", "reject"));
            area.insertAdjacentHTML("beforeend", `
                <span class="field-hint">Approving executes the reserved reward to the worker's submitted recipient. Rejecting releases the reservation.</span>`);
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
    if (kind === "claim") {
        payload = { recipient_address: document.getElementById("mkClaimAddr").value.trim() };
    } else if (kind === "submit") {
        const fileInput = document.getElementById("mkSubFiles");
        if (fileInput && fileInput.files && fileInput.files.length > 0) {
            await handleSubmissionFileInput(fileInput);
        }
        const notes = document.getElementById("mkSubNotes").value.trim();
        const url = document.getElementById("mkSubUrl").value.trim();
        if (!notes && !url && PENDING_SUBMISSION_FILES.length === 0) {
            const msg = document.getElementById("mkSubFileMsg");
            if (msg) {
                msg.setAttribute("role", "alert");
                msg.textContent = "Add work notes, a proof URL, or at least one attachment.";
            }
            return;
        }
        payload = {
            url,
            notes,
            submission_files: PENDING_SUBMISSION_FILES,
        };
    } else if (kind === "review") {
        payload = { action: sub, notes: (document.getElementById("mkRevNotes")?.value || "").trim() };
    }

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
    const createMsg = $("mkCreateMsg");
    if (createMsg) {
        createMsg.textContent = "";
        createMsg.removeAttribute("role");
    }
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
        CURRENT_LOGIN = me?.user?.login || "";
        authed = AgentPayAuth.renderLoginButton(githubLogin, me);
    } catch (error) {
        console.error("Failed to load marketplace auth state:", error);
        AgentPayAuth.renderLoginButton(githubLogin, null);
    }

    await loadTasks();
    await setupCreate(authed);
    startMarketplacePolling();
}

boot().catch((error) => {
    console.error("Marketplace boot failed:", error);
    setMarketplaceState("status--off", "Marketplace — unavailable");
});
