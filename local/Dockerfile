FROM rust:latest AS builder
WORKDIR /build
COPY . .
RUN rustup target add wasm32-unknown-unknown
RUN cargo install wasm-tools
RUN bash scripts/build-filters.sh
RUN cargo build --release -p s4-gateway

FROM debian:bookworm-slim
COPY --from=builder /build/target/release/s4-gateway /app/s4-gateway
COPY --from=builder /build/target/components/pii-default.component.wasm /app/pii-default.component.wasm
EXPOSE 8080
CMD ["/app/s4-gateway"]
