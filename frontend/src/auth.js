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
            document.body.classList.remove("is-authed");
            button.classList.remove("github-user");
            button.classList.remove("is-connected");
            button.removeAttribute("aria-label");
            button.href = "/auth/github";
            button.innerHTML = `
                Login with GitHub
                <span>↗</span>
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
        // Logged in, the chip is not a navigation target: no href (avoids the
        // "#" scroll-to-top jump), default cursor, and an accessible label.
        button.removeAttribute("href");
        button.setAttribute("aria-label", `Signed in as ${name}${login ? ` (${login})` : ""}`);

        button.innerHTML = `
            ${avatar
                ? `<img class="github-avatar" src="${escapeHtml(avatar)}" alt="${escapeHtml(name)}" data-initial="${escapeHtml(name)}">`
                : `<span class="github-avatar github-avatar--fallback" aria-hidden="true">${escapeHtml((name || "U").charAt(0).toUpperCase())}</span>`}

            <span class="github-user-info">
                <strong>${escapeHtml(name)}</strong>
                <small>${escapeHtml(login)}</small>
            </span>

            <span class="connected-badge">CONNECTED</span>

            <button type="button" class="logout-btn" id="logoutBtn">
                Logout
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
