#!/bin/bash
# PHASE 9 STEP H-4 — HARDENED SIGNER LAUNCH (deployment hardening).
#
# Launches the isolated signer under a DEDICATED OS USER with hardened
# process controls. Software-only; no hardware/cloud/vendor dependency.
#
# USAGE (root required to create the user; the run itself needs no root):
#   sudo bash tools/agentpay-signer/hardened_launch.sh <port> <store_dir>
#
# WHAT THIS ESTABLISHES (and what it does NOT — see the runbook):
#   * dedicated OS user `agentpay-signer` (AgentPay's user cannot read the
#     signer's store: the store dir is chowned to the signer user, 0700)
#   * no_new_privs (setpriv --no-new-privs): the signer cannot gain
#     privileges via setuid/sudo
#   * restricted environment (only the signer's own env names pass)
#   * loopback-only bind (enforced by the signer binary itself)
#   * the signer's store is outside artifact/ (never readable by AgentPay)
#
# WHAT THIS DOES NOT CLAIM: protection against root on this host, kernel
# compromise, or hardware attestation. Software-only boundary — see
# _phase9/hardened_signer_plane_runbook.md §Limitations.

set -euo pipefail

PORT="${1:?usage: hardened_launch.sh <port> <store_dir>}"
STORE="${2:?usage: hardened_launch.sh <port> <store_dir>}"
SIGNER_BIN="${AGENTPAY_SIGNER_BIN:-/opt/agentpay-signer/bin/agentpay-signer}"
RUN_USER="agentpay-signer"

# 1) the dedicated user (idempotent)
if ! getent passwd "$RUN_USER" >/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$RUN_USER"
    echo "hardened_launch: created system user $RUN_USER"
fi

# 2) the signer-owned store: owned by the signer user, 0700 (AgentPay's
#    user cannot read it; the funded keys are inaccessible to the app)
mkdir -p "$STORE"
chown -R "$RUN_USER:$RUN_USER" "$STORE"
chmod 700 "$STORE"

# 3) the binary must be readable by the signer user but NOT writable by
#    the app user (integrity: a pinned digest assumes a non-writable binary)
chgrp "$RUN_USER" "$SIGNER_BIN" 2>/dev/null || true
chmod 750 "$SIGNER_BIN" 2>/dev/null || true

# 4) the required env (the operator sets the channel pin / binary pin /
#    policy / provisioning allow-list OUTSIDE this script — never in chat)
: "${AGENTPAY_SIGNER_ENDPOINT:=127.0.0.1:${PORT}}"
: "${AGENTPAY_SIGNER_STORE:=${STORE}}"

# 5) launch: dedicated user + no_new_privs + a minimal environment
exec setpriv \
    --reuid "$RUN_USER" \
    --regid "$RUN_USER" \
    --clear-groups \
    --no-new-privs \
    --inh-caps=-all \
    env -i \
    PATH=/usr/bin:/bin \
    AGENTPAY_SIGNER_ENDPOINT="$AGENTPAY_SIGNER_ENDPOINT" \
    AGENTPAY_SIGNER_STORE="$AGENTPAY_SIGNER_STORE" \
    AGENTPAY_SIGNER_SIGNING_ENABLED="${AGENTPAY_SIGNER_SIGNING_ENABLED:-1}" \
    AGENTPAY_SIGNER_ADMIN_SECRET="${AGENTPAY_SIGNER_ADMIN_SECRET:-}" \
    AGENTPAY_SIGNER_POLICY="${AGENTPAY_SIGNER_POLICY:-}" \
    AGENTPAY_SIGNER_PROVISION_AGENTS="${AGENTPAY_SIGNER_PROVISION_AGENTS:-}" \
    AGENTPAY_SIGNER_CHANNEL_PUBKEY="${AGENTPAY_SIGNER_CHANNEL_PUBKEY:-}" \
    AGENTPAY_SIGNER_BINARY_PIN="${AGENTPAY_SIGNER_BINARY_PIN:-}" \
    "$SIGNER_BIN"
