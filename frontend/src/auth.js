/*
 * Shared GitHub session handling for AgentPay pages.
 *
 * Single source of truth for:
 *   - fetching the current session (/api/me)
 *   - rendering the navbar GitHub login / user chip
 *   - logout
 *   - HTML escaping
 *
 * Page-specific logic (wallet card, payment form) lives in wallet.js and
 * consumes AgentPayAuth. Navigation markup is owned by nav.js.
 */

const AgentPayAuth = (() => {
    function escapeHtml(value) {
        return String(value)
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#039;");
    }

    async function fetchMe() {
        try {
            const response = await fetch("/api/me", {
                method: "GET",
                credentials: "same-origin",
                cache: "no-store",
            });

            if (!response.ok) return null;

            const data = await response.json();

            return data.logged_in && data.user ? data : null;
        } catch (error) {
            console.error("Failed to load auth state:", error);
            return null;
        }
    }

    function walletProvider() {
        const candidates = [];
        if (Array.isArray(window.ethereum?.providers)) candidates.push(...window.ethereum.providers);
        if (window.ethereum) candidates.push(window.ethereum);
        if (window.okxwallet) candidates.push(window.okxwallet);
        if (window.rabby) candidates.push(window.rabby);
        return (
            candidates.find(
                (p) =>
                    p &&
                    typeof p.request === "function" &&
                    (p.isMetaMask || p.isOkxWallet || p.isOKExWallet || p.isRabby),
            ) || null
        );
    }

    function bytesToHex(bytes) {
        return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
    }

    async function walletLogin(button) {
        const provider = walletProvider();
        if (!provider) {
            window.location.href = "/auth/github";
            return;
        }

        const copy = button.querySelector(".github-login__copy strong");
        const note = button.querySelector(".github-login__copy small");
        const original = copy?.textContent || "Connect Wallet";
        button.setAttribute("aria-busy", "true");
        if (copy) copy.textContent = "Connecting...";
        if (note) note.textContent = "Approve in your wallet";

        try {
            const accounts = await provider.request({ method: "eth_requestAccounts" });
            const address = accounts?.[0];
            if (!address) throw new Error("Wallet did not return an account");

            const nonceResponse = await fetch("/auth/wallet/nonce", {
                method: "POST",
                credentials: "same-origin",
                headers: { "content-type": "application/json" },
                body: JSON.stringify({ address }),
            });
            const nonce = await nonceResponse.json();
            if (!nonceResponse.ok || !nonce.success || !nonce.message) {
                throw new Error(apiErrorMessage(nonce, "Could not start wallet login"));
            }

            const messageHex = "0x" + bytesToHex(new TextEncoder().encode(nonce.message));
            const signature = await provider.request({
                method: "personal_sign",
                params: [messageHex, address],
            });
            if (!signature || typeof signature !== "string") {
                throw new Error("Wallet did not return a signature");
            }

            const verifyResponse = await fetch("/auth/wallet/verify", {
                method: "POST",
                credentials: "same-origin",
                headers: { "content-type": "application/json" },
                body: JSON.stringify({
                    address,
                    nonce: nonce.nonce,
                    signature_hex: signature,
                }),
            });
            const verified = await verifyResponse.json();
            if (!verifyResponse.ok || !verified.success) {
                throw new Error(apiErrorMessage(verified, "Wallet login failed"));
            }
            window.location.reload();
        } catch (error) {
            console.error("Wallet login failed:", error);
            if (copy) copy.textContent = original;
            if (note) note.textContent = String(error?.message || "Wallet login failed").slice(0, 90);
            button.removeAttribute("aria-busy");
        }
    }

    /* deterministic initials fallback when the avatar is missing or fails */
    function avatarFallback(img) {
        const initial = (img.getAttribute("data-initial") || "U").charAt(0).toUpperCase();
        const span = document.createElement("span");
        span.className = "github-avatar github-avatar--fallback";
        span.textContent = initial;
        span.setAttribute("aria-hidden", "true");
        img.replaceWith(span);
    }

    /*
     * Render the navbar GitHub element.
     *   button — the .github-login element
     *   data   — full /api/me payload, or null when logged out
     * Returns the isLoggedIn boolean.
     *
     * This function is the single owner of the body.is-authed state class:
     * nav visibility rules (landing.css) key off it on every page, so page
     * scripts must not toggle it themselves.
     */
    function renderLoginButton(button, data) {
        if (!button) return false;

        if (!data || !data.user) {
            const provider = walletProvider();
            const wallet = !!provider;
            document.body.classList.remove("is-authed");
            button.classList.remove("github-user");
            button.classList.remove("is-connected");
            button.removeAttribute("aria-label");
            button.classList.toggle("wallet-available", wallet);
            button.href = wallet ? "#" : "/auth/github";
            button.onclick = wallet
                ? (event) => {
                      event.preventDefault();
                      walletLogin(button);
                  }
                : null;
            button.innerHTML = `
                <span class="github-login__icon" aria-hidden="true">
                    ${
                        wallet
                            ? `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><rect x="3" y="6" width="18" height="13" rx="2"/><path d="M3 10h18M16 15h2"/></svg>`
                            : `<svg viewBox="0 0 16 16" width="16" height="16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82A7.7 7.7 0 0 1 8 3.84c.68.01 1.36.09 2.01.27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z"/></svg>`
                    }
                </span>
                <span class="github-login__copy">
                    <strong>${wallet ? "Connect Wallet" : "Continue with GitHub"}</strong>
                    <small>${wallet ? "Sign a message — no keys shared" : "Secure OAuth session"}</small>
                </span>
                <span class="github-login__arr" aria-hidden="true">↗</span>
            `;
            return false;
        }

        const user = data.user;
        const name = user.name || user.login || "GitHub User";
        const login = user.login ? `@${user.login}` : "";
        const avatar = user.avatar_url || "";

        document.body.classList.add("is-authed");
        button.classList.add("github-user");
        button.classList.add("is-connected");
        button.classList.remove("wallet-available");
        button.onclick = null;
        // Logged in, the chip is not a navigation target: no href (avoids the
        // "#" scroll-to-top jump), default cursor, and an accessible label.
        button.removeAttribute("href");
        button.setAttribute("aria-label", `Signed in as ${name}${login ? ` (${login})` : ""}`);

        button.innerHTML = `
            <span class="github-user-avatar">
                ${avatar
                    ? `<img class="github-avatar" src="${escapeHtml(avatar)}" alt="${escapeHtml(name)}" data-initial="${escapeHtml(name)}">`
                    : `<span class="github-avatar github-avatar--fallback" aria-hidden="true">${escapeHtml((name || "U").charAt(0).toUpperCase())}</span>`}
                <span class="github-user-status" aria-hidden="true"></span>
            </span>

            <span class="github-user-info">
                <strong>${escapeHtml(name)}</strong>
                <small>${escapeHtml(login)}</small>
            </span>

            <span class="connected-badge">CONNECTED</span>

            <button type="button" class="logout-btn" id="logoutBtn">
                <span class="logout-btn__icon" aria-hidden="true">↪</span>
                <span class="logout-btn__label">Logout</span>
            </button>
        `;

        const avatarImg = button.querySelector("img.github-avatar");
        if (avatarImg) avatarImg.addEventListener("error", () => avatarFallback(avatarImg));

        bindLogout(document.getElementById("logoutBtn"));
        return true;
    }

    function bindLogout(logoutBtn) {
        logoutBtn?.addEventListener("click", async (event) => {
            event.preventDefault();
            event.stopPropagation();

            logoutBtn.disabled = true;
            logoutBtn.textContent = "Logging out...";

            try {
                const response = await fetch("/auth/logout", {
                    method: "POST",
                    credentials: "same-origin",
                    cache: "no-store",
                });

                if (!response.ok) {
                    throw new Error(`Logout failed: ${response.status}`);
                }

                window.location.href = "/";
            } catch (error) {
                console.error("Logout failed:", error);
                logoutBtn.disabled = false;
                logoutBtn.textContent = "Logout";
            }
        });
    }

    /*
     * Standard error shape returned by all AgentPay API endpoints:
     *   { success: false, error: { code, message } }
     */
    function apiErrorMessage(result, fallback) {
        const err = result?.error;

        if (!err) return fallback;
        if (typeof err === "string") return err;

        return `${err.code || "ERROR"}: ${err.message || "Request failed"}`;
    }

    return { escapeHtml, fetchMe, renderLoginButton, apiErrorMessage };
})();
