# syntax=docker/dockerfile:1
#
# Multi-stage build for Lodestar (authoritative DNS server + zone admin).
#   - builder: rust:1.96-slim (Debian trixie).
#   - runtime: debian:trixie-slim (matching glibc), non-root, ca-certificates.
#
# Like keyward/inkwell/sanctum, Lodestar links NO OpenSSL: the DNS server is hand-rolled over tokio
# UDP+TCP and sqlx uses `rustls` (ring), so the binary depends only on glibc — no libssl in either
# stage. The container HEALTHCHECK uses the built-in `lodestar healthcheck` subcommand (a raw-socket
# GET /healthz on the loopback), so no extra HTTP tool is needed in the image.

FROM rust:1.96-slim AS builder
WORKDIR /build

# Cache the dependency graph first: build a throwaway lib/bin against the real manifest so
# `cargo build` only recompiles our crate when src/ changes, not the whole tree.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN mkdir -p src \
    && echo 'fn main() {}' > src/main.rs \
    && echo '' > src/lib.rs \
    && cargo build --release --bin lodestar \
    && rm -rf src

# Now build the real binary. static/ + templates/ are include_str!'d into the binary, so they must
# be present at compile time.
COPY src ./src
COPY static ./static
COPY templates ./templates
RUN touch src/main.rs src/lib.rs \
    && cargo build --release --bin lodestar \
    && strip target/release/lodestar

FROM debian:trixie-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user (no shell, no home writes needed).
RUN useradd --system --uid 10001 --user-group --no-create-home lodestar
COPY --from=builder /build/target/release/lodestar /usr/local/bin/lodestar

USER lodestar
# Default in-container binds; overridable at runtime. The DNS server listens on the ALT port :5353
# (UDP + TCP) — NEVER the privileged :53; go-live is a deliberate registrar NS cutover by a human.
ENV BIND_ADDR=0.0.0.0:9110
ENV LODESTAR_DNS_ADDR=0.0.0.0:5353
EXPOSE 9110
EXPOSE 5353/udp
EXPOSE 5353/tcp

# Dependency-free liveness probe -> GET /healthz on the loopback, exit 0/1.
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD ["lodestar", "healthcheck"]

ENTRYPOINT ["lodestar"]
