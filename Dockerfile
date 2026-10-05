# ── Builder stage ─────────────────────────────────────────────────────────────
FROM rust:1.80-slim-bookworm AS builder

# Install only what's needed for native-tls / OpenSSL
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cache dependency compilation
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main(){}" > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src

# Build actual binary
COPY src ./src
RUN touch src/main.rs && cargo build --release --locked

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/randerx ./randerx

EXPOSE 3000
CMD ["./randerx"]
