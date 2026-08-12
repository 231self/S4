# syntax=docker/dockerfile:1
# Optimized deploy image for S4 gateway.
# Pre-built Wasm components committed to components/; single arch (amd64).

FROM rust:1-bookworm AS build
WORKDIR /src

# Dependencies first — this layer caches across source changes.
COPY Cargo.toml Cargo.lock ./
COPY crates/error/Cargo.toml crates/error/
COPY crates/wasm-runtime/Cargo.toml crates/wasm-runtime/
COPY crates/gateway/Cargo.toml crates/gateway/
COPY crates/s4ctl/Cargo.toml crates/s4ctl/
COPY filters/email-detect/Cargo.toml filters/email-detect/
COPY filters/ssn-detect/Cargo.toml filters/ssn-detect/
COPY filters/card-detect/Cargo.toml filters/card-detect/
COPY filters/pii-default/Cargo.toml filters/pii-default/
COPY filters/pii-shared/Cargo.toml filters/pii-shared/
COPY filters/envelope-encrypt/Cargo.toml filters/envelope-encrypt/
COPY filters/stable-encrypt/Cargo.toml filters/stable-encrypt/
COPY filters/noop/Cargo.toml filters/noop/

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo fetch

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p s4-gateway \
    && cp /src/target/release/s4-gateway /src/gateway-bin

FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/gateway-bin /usr/local/bin/s4-gateway
COPY components /app/components
ENV S4_FILTER_COMPONENT=/app/components/pii-default.component.wasm
ENV S4_PLUGINS_DIR=/app/components
ENV LISTEN_ADDR=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["s4-gateway"]
