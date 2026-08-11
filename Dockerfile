# syntax=docker/dockerfile:1
# Deploy image for the S4 gateway: release binary + Wasm filter components.
#
# Build:      docker build -t s4-gateway .
# Via CI:     .github/workflows/release.yml (docker/build-push-action, gha cache)
# Locally:    dagger call publish --tag=... (see dagger/main.py)
#
# Multi-arch: buildx platforms linux/amd64,linux/arm64. The gateway is
# cross-compiled per TARGETARCH so both platforms build natively in buildkit
# (no QEMU), and cargo registry + target dirs ride on BuildKit cache mounts
# so incremental builds reuse compiled deps.

FROM rust:1-bookworm AS build
WORKDIR /src

ARG TARGETARCH

# Cross toolchain for the arm64 build (no-op cost on amd64).
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu \
    && rm -rf /var/lib/apt/lists/*

# Rust 2024 edition requires a recent toolchain; rust:1 tracks latest.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    rustup target add wasm32-unknown-unknown \
    && if [ "$TARGETARCH" = "arm64" ]; then rustup target add aarch64-unknown-linux-gnu; fi \
    && cargo install --locked wasm-tools --version 1.255.0 --root /opt/wasm-tools
ENV PATH="/opt/wasm-tools/bin:$PATH"

COPY . .

# Wasm filter components (pii-default, envelope-encrypt, stable-encrypt, ...)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    bash scripts/build-filters.sh

# Release gateway binary, compiled for the target architecture
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    if [ "$TARGETARCH" = "arm64" ]; then \
        CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
        cargo build --release --target aarch64-unknown-linux-gnu -p s4-gateway; \
    else \
        cargo build --release -p s4-gateway; \
    fi

RUN if [ "$TARGETARCH" = "arm64" ]; then \
        cp /src/target/aarch64-unknown-linux-gnu/release/s4-gateway /src/gateway-bin; \
    else \
        cp /src/target/release/s4-gateway /src/gateway-bin; \
    fi

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/gateway-bin /usr/local/bin/s4-gateway
COPY --from=build /src/target/components /app/components

ENV S4_FILTER_COMPONENT=/app/components/pii-default.component.wasm
ENV S4_PLUGINS_DIR=/app/components
ENV LISTEN_ADDR=0.0.0.0:8080
EXPOSE 8080

ENTRYPOINT ["s4-gateway"]
