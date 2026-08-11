# syntax=docker/dockerfile:1
# Deploy image for the S4 gateway: release binary + Wasm filter components.
#
# Stages:
#   filters — Wasm components are architecture-independent, built ONCE here
#   build   — per-arch gateway release binary (TARGETARCH)
#   runtime — debian:trixie-slim + binary + components
#
# Multi-arch: buildx platforms linux/amd64,linux/arm64; the gateway is
# cross-compiled for arm64 (gcc-aarch64-linux-gnu), so both platforms build
# natively with no QEMU. Cargo registry + target ride on BuildKit cache
# mounts so repeat builds reuse compiled deps.

FROM rust:1-bookworm AS filters
WORKDIR /src

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    rustup target add wasm32-unknown-unknown \
    && cargo install --locked wasm-tools --version 1.255.0 --root /opt/wasm-tools
ENV PATH="/opt/wasm-tools/bin:$PATH"

COPY . .

# Wasm filter components (pii-default, envelope-encrypt, stable-encrypt, ...)
# Copied out of the cache mount to a stable path for the runtime stage.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    bash scripts/build-filters.sh \
    && cp -r /src/target/components /src/components-out

FROM rust:1-bookworm AS build
WORKDIR /src
ARG TARGETARCH

# Cross toolchain for the arm64 build.
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu \
    && rm -rf /var/lib/apt/lists/*

COPY . .

# Release gateway binary, compiled for the target architecture, then copied
# out of the cache mount to a stable path.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    if [ "$TARGETARCH" = "arm64" ]; then \
        rustup target add aarch64-unknown-linux-gnu \
        && CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
        cargo build --release --target aarch64-unknown-linux-gnu -p s4-gateway \
        && cp /src/target/aarch64-unknown-linux-gnu/release/s4-gateway /src/gateway-bin; \
    else \
        cargo build --release -p s4-gateway \
        && cp /src/target/release/s4-gateway /src/gateway-bin; \
    fi

FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/gateway-bin /usr/local/bin/s4-gateway
COPY --from=filters /src/components-out /app/components
ENV S4_FILTER_COMPONENT=/app/components/pii-default.component.wasm
ENV S4_PLUGINS_DIR=/app/components
ENV LISTEN_ADDR=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["s4-gateway"]
