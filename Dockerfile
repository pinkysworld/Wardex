# Wardex — multi-stage container build
# Usage:
#   docker build -t wardex .
#   docker run -p 9077:9077 -v wardex-data:/app/var wardex

# ── Stage 1: Build ────────────────────────────────────────────────
FROM rust:1.85-bookworm AS builder
COPY --from=node:22-bookworm /usr/local/ /usr/local/

WORKDIR /build

# Copy the full build inputs so Cargo and build.rs see a consistent project.
COPY Cargo.toml Cargo.lock* ./
COPY build.rs ./
COPY src/ src/
COPY admin-console/ admin-console/
COPY site/ site/
COPY examples/ examples/
COPY benches/ benches/
COPY tests/ tests/

RUN npm ci --prefix admin-console
RUN cargo build --release --features tls --bin wardex \
    && strip target/release/wardex

# ── Stage 2: Runtime ──────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Non-root user for security
RUN groupadd -r wardex && useradd -r -g wardex -d /app -s /sbin/nologin wardex

WORKDIR /app
COPY --from=builder /build/target/release/wardex /app/wardex
COPY site/ /app/site/
COPY examples/ /app/examples/

RUN mkdir -p /app/var && chown -R wardex:wardex /app

USER wardex

EXPOSE 9077

VOLUME ["/app/var"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/app/wardex", "status-json"]

ENTRYPOINT ["/app/wardex"]
CMD ["serve", "--port", "9077"]
