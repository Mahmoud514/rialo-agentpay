/*
 * Wallet page: wallet card, balance, faucet, copy-address.
 * GitHub session widget, logout, escaping, and API error formatting are
 * shared via AgentPayAuth (auth.js) — do not duplicate them here.
 */

const githubLogin = document.querySelector(".github-login");

function setBalance(value) {
    const walletBalance = document.getElementById("walletBalance");

    if (!walletBalance) return;

    const match = String(value || "").match(/([\d.]+)\s*RLO/i);

    walletBalance.textContent = match ? `${match[1]} RLO` : (value || "—");
}

function setWalletState(kind, text) {
    const el = document.getElementById("walletStateIndicator");
    if (!el) return;
    el.className = "status " + kind;
    const label = el.querySelector(".status__label");
    if (label) label.textContent = text;
}

function setGate(loggedInWithWallet) {
    const gate = document.getElementById("paymentGate");
    const card = document.getElementById("paymentCard");
    if (gate) gate.hidden = loggedInWithWallet;
    if (card) card.hidden = !loggedInWithWallet;
}

function showLoginRequired() {
    const walletAddress = document.getElementById("walletAddress");
    const walletBalance = document.getElementById("walletBalance");
    const faucetBtn = document.getElementById("faucetBtn");
    const copyWallet = document.getElementById("copyWallet");

    if (walletAddress) {
        walletAddress.textContent = "Not available — sign in required";
        walletAddress.classList.add("is-placeholder");
    }
    if (walletBalance) {
        walletBalance.textContent = "—";
        walletBalance.classList.add("is-na");
    }

    if (faucetBtn) faucetBtn.disabled = true;
    if (copyWallet) copyWallet.disabled = true;

    // plain text: this lands in textContent (see setWalletState), so the
    // old "&nbsp;" entity string rendered literally. Use a real space.
    setWalletState("status--na", "Not Signed In");
    setGate(false);

    AgentPayAuth.renderLoginButton(githubLogin, null);
}

function renderWalletCard(data) {
    const walletAddress = document.getElementById("walletAddress");
    const walletBalance = document.getElementById("walletBalance");
    const copyWallet = document.getElementById("copyWallet");
    const faucetBtn = document.getElementById("faucetBtn");
    const paymentCard = document.getElementById("paymentCard");

    const address = data.wallet_address || "Not available";

    if (paymentCard) paymentCard.hidden = !data.wallet_address;
    setGate(Boolean(data.wallet_address));

    if (walletAddress) {
        walletAddress.textContent = address;
        walletAddress.classList.toggle("is-placeholder", !data.wallet_address);
    }

    // Explicit balance status from the backend — never fake a zero when the
    // Rialo RPC is unavailable.
    if (data.balance_status === "ok" && data.balance) {
        setBalance(data.balance);
        walletBalance?.classList.remove("is-na");
    } else if (walletBalance) {
        const code = data.balance_error?.code || "";
        walletBalance.textContent = code === "RIALO_RPC_UNAVAILABLE"
            ? "RPC unavailable"
            : "—";
        walletBalance.classList.add("is-na");
        if (code) {
            walletBalance.title = `${code}: ${data.balance_error?.message || ""}`;
        }
    }

    // Honest card status: connected / address-only when RPC is down / no wallet.
    if (!data.wallet_address) {
        setWalletState("status--warn", "Signed in — no wallet yet");
    } else if (data.balance_status === "ok") {
        setWalletState("status--on", "Connected");
    } else {
        setWalletState("status--warn", "RPC unavailable");
    }

    copyWallet?.addEventListener("click", async () => {
        try {
            await navigator.clipboard.writeText(address);

            copyWallet.textContent = "Copied ✓";

            setTimeout(() => {
                copyWallet.textContent = "Copy";
            }, 1500);
        } catch (error) {
            console.error("Copy failed:", error);
        }
    });

    faucetBtn?.addEventListener("click", async () => {
        faucetBtn.disabled = true;
        faucetBtn.innerHTML = "Requesting...";

        try {
            const response = await fetch("/api/faucet", {
                method: "POST",
                credentials: "same-origin",
                cache: "no-store",
            });

            const result = await response.json();

            if (!response.ok || !result.success) {
                throw new Error(
                    AgentPayAuth.apiErrorMessage(result, "Faucet request failed")
                );
            }

            faucetBtn.innerHTML = "Received ✓";

            // Refresh the page after the faucet transaction is confirmed
            setTimeout(() => {
                window.location.reload();
            }, 3000);
        } catch (error) {
            console.error("Faucet failed:", error);

            faucetBtn.innerHTML = "Failed";
            faucetBtn.title = error.message;

            // Refresh balance display in case the error was an RPC outage.
            loadWallet();
        } finally {
            setTimeout(() => {
                faucetBtn.innerHTML = `
                    Get 1 RLO
                    <span>→</span>
                `;
                faucetBtn.disabled = false;
                faucetBtn.title = "";
            }, 1800);
        }
    });

    wirePaymentForm();
}

// ---------------------------------------------------------------------------
// Direct payment form (POST /api/payment). The program-mediated payment path
// is intentionally NOT exposed here — /api/payment is the normal route.
// ---------------------------------------------------------------------------
function setPaymentStatus(message, kind) {
    const status = document.getElementById("paymentStatus");
    if (!status) return;
    status.textContent = message || "";
    status.className = `payment-status ${kind || ""}`.trim();
}

function validRialoAddressClient(addr) {
    return /^[A-Za-z0-9]{32,44}$/.test(addr);
}

function wirePaymentForm() {
    const form = document.getElementById("paymentForm");
    const recipientInput = document.getElementById("paymentRecipient");
    const amountInput = document.getElementById("paymentAmount");
    const sendBtn = document.getElementById("sendPaymentBtn");
    const resultBox = document.getElementById("paymentResult");
    const signatureEl = document.getElementById("paymentSignature");

    if (!form || form.dataset.wired === "1") return;
    form.dataset.wired = "1";

    form.addEventListener("submit", async (event) => {
        event.preventDefault();

        const recipient = (recipientInput?.value || "").trim();
        const amount = parseFloat(amountInput?.value || "");

        // Client-side pre-validation mirrors the server's rules so obvious
        // mistakes never hit the API; the server re-validates everything.
        if (!validRialoAddressClient(recipient)) {
            setPaymentStatus("Recipient must be 32-44 alphanumeric characters.", "error");
            return;
        }
        if (!Number.isFinite(amount) || amount <= 0) {
            setPaymentStatus("Amount must be a positive number of RLO.", "error");
            return;
        }

        sendBtn.disabled = true;
        sendBtn.innerHTML = "Sending...";
        if (resultBox) resultBox.hidden = true;
        setPaymentStatus("Submitting payment...", "pending");

        try {
            const response = await fetch("/api/payment", {
                method: "POST",
                credentials: "same-origin",
                cache: "no-store",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ to: recipient, amount }),
            });

            const result = await response.json();

            if (!response.ok || !result.success) {
                const code = result?.error?.code || "";
                const message = AgentPayAuth.apiErrorMessage(result, "Payment failed");
                throw new Error(code ? `[${code}] ${message}` : message);
            }

            setPaymentStatus("Payment sent ✓", "success");

            if (signatureEl) signatureEl.textContent = result.signature || "(no signature returned)";
            if (resultBox) resultBox.hidden = false;

            // Refresh the balance card with the authoritative server state.
            loadWallet();

            if (recipientInput) recipientInput.value = "";
            if (amountInput) amountInput.value = "";
        } catch (error) {
            // INSUFFICIENT_FUNDS / RIALO_RPC_UNAVAILABLE / INVALID_* all
            // surface here with their stable codes — never shown as a fake
            // zero balance or a silent failure.
            setPaymentStatus(error.message, "error");
            loadWallet();
        } finally {
            setTimeout(() => {
                sendBtn.innerHTML = `
                    Send Payment
                    <span>→</span>
                `;
                sendBtn.disabled = false;
            }, 1200);
        }
    });
}

async function loadWallet() {
    const data = await AgentPayAuth.fetchMe();

    if (!data) {
        showLoginRequired();
        return;
    }

    AgentPayAuth.renderLoginButton(githubLogin, data);
    renderWalletCard(data);
}

loadWallet();
