# syntax=docker/dockerfile:1
# Rialo AgentPay — multi-stage build
# Build context: repository root. Requires BuildKit.

# ---------------------------------------------------------------- builder ---
# rust:1.91-slim ship with rustup — we install the pinned nightly toolchain.
FROM rust:1.91-slim AS builder

WORKDIR /build

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

# --------------------------------------------------------------- runtime ---
FROM debian:trixie-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --create-home --home-dir /app --uid 10001 agentpay

WORKDIR /app

COPY --from=builder /build/target/release/server /app/server

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
