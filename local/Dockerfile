FROM rust:1.97.0-trixie@sha256:b92b8c8574f8f3b207fcb0912fb3e2de4041580b5934d90312d53938c9a038a9 AS builder
WORKDIR /build
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    rustup target add wasm32-wasip1 \
    && cargo install --locked wasm-tools --version 1.255.0
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    bash scripts/build-filters.sh
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release -p s4-gateway

FROM debian:trixie-slim@sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/s4-gateway /app/s4-gateway
COPY --from=builder /build/target/components/pii-default.component.wasm /app/pii-default.component.wasm
EXPOSE 8080
CMD ["/app/s4-gateway"]
