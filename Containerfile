# SPDX-License-Identifier: Apache-2.0

FROM rust:1.96-slim-bookworm AS build
ARG TARGETARCH
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY rust/app/Cargo.toml rust/app/
COPY rust/app/src rust/app/src
COPY rust/app/migrations rust/app/migrations
# Rebuild the workspace package when this layer changes, even with older source timestamps.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,id=context-forge-rs-release-${TARGETARCH},target=/src/target,sharing=locked \
    cargo clean --locked --release --package context-forge-rs \
    && CARGO_PROFILE_RELEASE_STRIP=debuginfo cargo build --locked --release --workspace --bins \
    && install -D target/release/context-forge-rs /out/context-forge-rs \
    && install -D target/release/context-forge-translate /out/context-forge-translate

FROM debian:bookworm-slim
LABEL org.opencontainers.image.source="https://github.com/lucarlig/context-forge-rs" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* /usr/share/gcc/python /usr/share/gdb/auto-load \
    && groupadd --gid 10001 context-forge \
    && useradd --uid 10001 --gid 10001 --no-create-home --no-log-init \
        --home-dir /var/lib/context-forge --shell /usr/sbin/nologin context-forge \
    && install -d -m 0700 -o 10001 -g 10001 /var/lib/context-forge

COPY --from=build /out/ /usr/local/bin/
COPY LICENSE /usr/share/doc/context-forge-rs/LICENSE

ENV HOST=0.0.0.0 \
    PORT=4444 \
    DATABASE_URL=sqlite:////var/lib/context-forge/mcp.db
WORKDIR /var/lib/context-forge
USER 10001:10001
EXPOSE 4444
HEALTHCHECK --interval=15s --timeout=6s --start-period=30s --retries=3 \
    CMD curl --fail --silent --show-error --noproxy '*' --max-time 5 \
        "http://127.0.0.1:${PORT}/ready" --output /dev/null
ENTRYPOINT ["/usr/local/bin/context-forge-rs"]
