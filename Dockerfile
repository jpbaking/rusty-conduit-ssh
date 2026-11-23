# syntax=docker/dockerfile:1

FROM rust:1-bookworm AS builder
WORKDIR /src

# Cache dependency compilation separately from source changes.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && printf 'pub fn _stub() {}\n' > src/lib.rs \
    && printf 'fn main() {}\n' > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src

COPY src ./src
RUN touch src/lib.rs src/main.rs \
    && cargo build --release --locked

FROM ubuntu:26.04 AS base
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get dist-upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home --home-dir /home/rusty-conduit-ssh --shell /usr/sbin/nologin rusty-conduit-ssh

LABEL org.opencontainers.image.title="rusty-conduit-ssh" \
      org.opencontainers.image.description="Single-binary HTTP/HTTPS and SOCKS4/4a/5 forward proxy that routes all upstream traffic and DNS through an auto-reconnecting SSH dynamic tunnel" \
      org.opencontainers.image.source="https://github.com/jpbaking/rusty-conduit-ssh" \
      org.opencontainers.image.licenses="BSD-3-Clause"

ENV RUSTY_CONDUIT_SSH_BIND=0.0.0.0

EXPOSE 3128 1080
USER rusty-conduit-ssh
ENTRYPOINT ["/usr/local/bin/rusty-conduit-ssh"]

# Fast multi-arch packaging target for CI (uses native binaries built in release.yml).
FROM base AS prebuilt
ARG TARGETARCH
COPY --chmod=0755 dist/linux-${TARGETARCH}/rusty-conduit-ssh /usr/local/bin/rusty-conduit-ssh

# Default target for local `docker build .` and CI Dockerfile validation.
FROM base AS runtime
COPY --from=builder --chmod=0755 /src/target/release/rusty-conduit-ssh /usr/local/bin/rusty-conduit-ssh
