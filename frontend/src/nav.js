/*
 * Rialo AgentPay — shared navbar component (navigation markup only).
 *
 * Consumed by every page: index.html (landing) plus the seven app pages
 * (wallet.html, dashboard.html, agents.html, marketplace.html,
 * activity.html, leaderboard.html, verify.html). Each page carries a minimal
 * static fallback inside [data-agentpay-nav] (brand + auth slot); this module
 * replaces it with the full navigation. No framework, no build step.
 *
 * Responsibilities (this file ONLY):
 *   - render brand, marketing anchor links, app links (Home / Wallet /
 *     Dashboard / Agents / Leaderboard / Activity / Verify)
 *   - page-aware link prefixes: landing uses "#anchor" for marketing links;
 *     app pages use "/#anchor" except "Leaderboard", which targets the real
 *     /leaderboard.html page (an anchor would scroll the current page and
 *     land on nothing)
 *   - active state for the current app page
 *   - .nav__app-links--always on app pages (visible before login)
 *
 * NOT responsible for: auth state, the user chip, or logout — the
 * .github-login slot belongs to AgentPayAuth (auth.js) as before.
 *
 * Script order per page: nav.js -> auth.js -> page script. nav.js renders
 * synchronously at parse time (scripts sit at end of <body>), so the
 * .github-login element it outputs is present when auth.js queries it.
 */

const AgentPayNav = (() => {
    const MARKETING_LINKS = [
        // [id, label, realPage] — realPage (when present) is the app page the
        // anchor describes, and doubles as the link target on app pages, where
        // a "#anchor" would scroll the CURRENT app page and land on nothing.
        ["premise", "Product"],
        ["how", "How&nbsp;It&nbsp;Works"],
        ["architecture", "Architecture"],
        ["leaderboard", "Leaderboard", "/leaderboard"],
        ["faq", "FAQ"],
    ];

    const APP_LINKS = [
        ["Home", "/"],
        ["Marketplace", "/marketplace"],
        ["Wallet", "/wallet"],
        ["Dashboard", "/dashboard"],
        ["Agents", "/agents"],
        ["Leaderboard", "/leaderboard"],
        ["Activity", "/activity"],
        ["Verify", "/verify"],
    ];

    function normalizePath(pathname) {
        // "/index.html" and "/" are the same page; "/wallet.html" /
        // "/dashboard.html" match their APP_LINKS entries verbatim.
        // Extensionless paths (the canonical serve form) map onto their
        // APP_LINKS entries so the active state keeps working.
        if (pathname === "/index.html") return "/";
        if (pathname === "/agents") return "/agents";
        if (pathname === "/marketplace") return "/marketplace";
        if (pathname === "/leaderboard") return "/leaderboard";
        if (pathname === "/activity") return "/activity";
        if (pathname === "/verify") return "/verify";
        // Map old .html paths to clean URLs for backward compatibility
        if (pathname === "/wallet.html") return "/wallet";
        if (pathname === "/dashboard.html") return "/dashboard";
        if (pathname === "/agents.html") return "/agents";
        if (pathname === "/leaderboard.html") return "/leaderboard";
        if (pathname === "/activity.html") return "/activity";
        if (pathname === "/verify.html") return "/verify";
        return pathname;
    }

    function render(mount) {
        if (!mount) return;

        // App pages carry body.app-body (wallet, dashboard, agents,
        // activity, leaderboard, verify); the landing does not. The active
        // app link is derived generically from the current pathname so every
        // entry in APP_LINKS self-highlights
        // (/, /wallet.html, /dashboard.html, /agents.html, /activity.html,
        // /leaderboard.html, /verify.html) without page-specific code.
        const isApp = document.body.classList.contains("app-body");
        const anchorPrefix = isApp ? "/" : "";
        const currentPath = normalizePath(location.pathname);

        const marketing = MARKETING_LINKS
            .map(([id, label, realPage], index) => {
                // On the landing, every marketing link is a same-page anchor.
                // On app pages a "#anchor" would scroll the CURRENT app page
                // and land on nothing, so the "Leaderboard" marketing link
                // targets the real /leaderboard.html page there instead.
                const href = isApp && realPage ? realPage : `${anchorPrefix}#${id}`;
                return `            <a class="nav__link" style="--i:${index}" href="${href}">${label}</a>`;
            })
            .join("\n");

        const appLinks = APP_LINKS
            .map(([label, href], index) => {
                const active = href === currentPath;
                return `                <a class="btn btn--ghost btn--sm${active ? " is-active" : ""}" style="--i:${index}" href="${href}"${active ? ' aria-current="page"' : ""}>${label}</a>`;
            })
            .join("\n");

        mount.innerHTML = `
        <a class="brand" href="/">
            <span class="brand__mark brand__mark--logo" aria-hidden="true"><img src="/assets/logo-mark.png" alt=""></span>
            <span class="brand__name">Rialo&nbsp;<b>AgentPay</b></span>
        </a>

        <div class="nav__links">
${marketing}
        </div>

        <div class="nav__right">
            <div class="nav__app-links${isApp ? " nav__app-links--always" : ""}" aria-label="Application">
${appLinks}
            </div>
            <a class="github-login" href="/auth/github">Login with GitHub <span>↗</span></a>
        </div>
    `;
    }

    function init() {
        const mount = document.querySelector("[data-agentpay-nav]");
        if (!mount) return;
        render(mount);
    }

    init();

    return { init };
})();
