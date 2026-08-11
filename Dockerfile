# syntax=docker/dockerfile:1
# Deploy image for the S4 gateway: release binary + Wasm filter components.
#
# Build:      docker build -t s4-gateway .
# Via CI:     .github/workflows/release.yml (docker/build-push-action, gha cache)
# Locally:    dagger call publish --tag=... (see dagger/main.py)
#
# Cargo registry + target dirs ride on BuildKit cache mounts so incremental
# builds reuse compiled deps instead of recompiling everything.

FROM rust:1-bookworm AS build
WORKDIR /src

# Rust 2024 edition requires a recent toolchain; rust:1 tracks latest.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    rustup target add wasm32-unknown-unknown \
    && cargo install --locked wasm-tools --version 1.255.0 --root /opt/wasm-tools
ENV PATH="/opt/wasm-tools/bin:$PATH"

COPY . .

# Wasm filter components (pii-default, envelope-encrypt, stable-encrypt, ...)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    bash scripts/build-filters.sh

# Release gateway binary
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p s4-gateway

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/target/release/s4-gateway /usr/local/bin/s4-gateway
COPY --from=build /src/target/components /app/components

ENV S4_FILTER_COMPONENT=/app/components/pii-default.component.wasm
ENV S4_PLUGINS_DIR=/app/components
ENV LISTEN_ADDR=0.0.0.0:8080
EXPOSE 8080

ENTRYPOINT ["s4-gateway"]
