# Rialo AgentPay — multi-stage build
# Build context: repository root. Requires BuildKit.

# ---------------------------------------------------------------- builder ---
# rust:1.91-slim ship with rustup — we install the pinned nightly toolchain.
FROM rust:1.91-slim AS builder

WORKDIR /build

# G21 — wget is absent in rust:*-slim (proven: /bin/sh: 1: wget: not found,
# exit 127, docker-build run 39251171237). Install it upfront so the pinned
# CLI fetch step below works; lists cleaned afterwards per base-image habit.
RUN apt-get update \
    && apt-get install -y --no-install-recommends wget \
    && rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install nightly --profile minimal

# Dependency-cache layer: manifests only.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src/bin/server examples && \
    echo "fn main() {}" > src/main.rs && \
    echo "fn main() {}" > src/bin/server.rs && \
    echo "fn main() {}" > examples/wallet_registry_backfill.rs && \
    cargo fetch --locked

# Full source needed for the real build (wit/ is used by a build-script
# generator that runs during `cargo build`).
COPY src/ src/
COPY wit/ wit/

# Exact CI feature flag + lockfile. Release in the final image.
RUN cargo +nightly build --release --features server --bin server --locked

# ----------------------------------------------------------- rialo CLI ------
# G21 — pinned Rialo CLI 0.18.1 (linux-amd64), fetched at build time from the
# repository's own pinned GitHub Release asset (public, operator-controlled).
# The runtime image previously shipped WITHOUT the CLI, which made every
# CLI-backed money path (direct payment transfer, faucet airdrop) fail with
# RIALO_CLI_UNAVAILABLE → 502. Build-time integrity: hard `sha256sum -c`
# gate against the pinned digest — any tamper/absence fails the build.
# (Provenance notes: vendor/RIALO_CLI_PROVENANCE.md.)
ARG RIALO_CLI_RELEASE_URL=https://github.com/Mahmoud514/rialo-agentpay/releases/download/rialo-cli-0.18.1/binaries-stable-0.18.1-linux-amd64.tar.gz
RUN wget -qO /tmp/rialo-cli.tar.gz "$RIALO_CLI_RELEASE_URL" \
    && echo "652c94e14d0744f617988199515bbad1977fe40390b0a998928c1e2bb7e6af69  /tmp/rialo-cli.tar.gz" \
      | sha256sum -c - \
    && mkdir -p /opt/rialo-cli \
    && tar -xzf /tmp/rialo-cli.tar.gz -C /opt/rialo-cli --strip-components=1 bin/rialo \
    && chmod 0755 /opt/rialo-cli/rialo \
    && rm /tmp/rialo-cli.tar.gz

# --------------------------------------------------------------- runtime ---
FROM debian:trixie-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --create-home --home-dir /app --uid 10001 agentpay

WORKDIR /app

COPY --from=builder /build/target/release/server /app/server

# G21 — the pinned rialo CLI (built in the builder stage from the vendored,
# checksum-verified 0.18.1 vendor bundle). Server resolves the CLI from PATH
# (RialoConfig.cli defaults to `rialo`), so a symlink into /usr/local/bin
# makes every CLI-backed money path work without code changes.
COPY --from=builder /opt/rialo-cli/rialo /opt/rialo-cli/rialo
RUN chmod 0755 /opt/rialo-cli/rialo \
    && ln -s /opt/rialo-cli/rialo /usr/local/bin/rialo \
    && /usr/local/bin/rialo --version

# Static frontend is served by the same process (ServeDir; no build step).
COPY frontend/src/ /app/frontend/src/

# Writable state root (agent records / stray mode-fs locals). Funded wallet
# keypairs are NEVER included (see .dockerignore) — the isolated signer
# stays OUT of this image by design.
RUN mkdir -p /app/artifact && chown -R agentpay:agentpay /app

USER agentpay

# The server binds SERVER_ADDR (default 127.0.0.1:8080 → useless in a
# container). 0.0.0.0 + the platform port; overridden via env at deploy time.
ENV SERVER_ADDR=0.0.0.0:8000

# Fail-safe default for any hosted launch: transfers OFF unless the owner
# explicitly overrides this env at the platform level. Behavior is
# CI-proven (transfer-killswitch-enabled job): 503 TRANSFERS_DISABLED
# before any balance read, reservation, signing, or submission.
ENV AGENTPAY_DISABLE_TRANSFERS=1

EXPOSE 8000

# Unauthenticated liveness probe: /api/health returns booleans + block
# height only; touches no privileged or payment path.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/api/health || exit 1

ENTRYPOINT ["/app/server"]
