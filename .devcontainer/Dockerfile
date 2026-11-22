# Development container for kanbot: the Rust backend and the Flutter app,
# with every tool the checks in backend/AGENTS.md and frontend/AGENTS.md use.
# Docker (for compose: Postgres, Authelia and Keycloak) comes from the docker-in-docker
# feature in devcontainer.json.
#
# Every download is pinned: images by digest, rustup-init by checksum,
# Flutter by commit, crates by version (--locked).
FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04@sha256:d94c97dd9cacf183d0a6fd12a8e87b526e9e928307674ae9c94139139c0c6eae

ARG TARGETARCH

# renovate: datasource=github-tags depName=rust-lang/rustup
ARG RUSTUP_VERSION=1.29.3
ARG RUSTUP_SHA256_AMD64=b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55
ARG RUSTUP_SHA256_ARM64=9f608c142e0e38a78957d0661ba1dfaf0b6fb37184cfaa4b9a0aa57af6184282
# The toolchain of backend/rust-toolchain.toml, preinstalled.
ARG RUST_TOOLCHAIN=1.100.0
# renovate: datasource=crate depName=sqlx-cli
ARG SQLX_CLI_VERSION=0.9.1
# renovate: datasource=crate depName=cargo-deny
ARG CARGO_DENY_VERSION=0.22.0
# renovate: datasource=crate depName=cargo-llvm-cov
ARG CARGO_LLVM_COV_VERSION=0.9.1
# renovate: datasource=crate depName=cargo-mutants
ARG CARGO_MUTANTS_VERSION=27.1.0
# renovate: datasource=flutter-version depName=flutter
ARG FLUTTER_VERSION=3.50.0
ARG FLUTTER_COMMIT=ab2912035e160d9cad6306df307576da6128ebdb

# Build dependencies: OpenSSL for reqwest's native-tls (backend/AGENTS.md
# §5), and the Linux desktop toolchain plus libsecret for
# flutter_secure_storage and WebKitGTK for flutter_web_auth_2
# (frontend/AGENTS.md §10).
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential pkg-config libssl-dev openssl \
      clang cmake ninja-build libgtk-3-dev libsecret-1-dev \
      libwebkit2gtk-4.1-dev libsoup-3.0-dev \
      curl git unzip xz-utils zip ca-certificates \
 && rm -rf /var/lib/apt/lists/*

USER vscode
ENV RUSTUP_HOME=/home/vscode/.rustup \
    CARGO_HOME=/home/vscode/.cargo \
    PATH=/home/vscode/.cargo/bin:/home/vscode/flutter/bin:$PATH

RUN case "$TARGETARCH" in \
      amd64) target=x86_64-unknown-linux-gnu; sum=$RUSTUP_SHA256_AMD64 ;; \
      arm64) target=aarch64-unknown-linux-gnu; sum=$RUSTUP_SHA256_ARM64 ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac \
 && curl -fsSL -o /tmp/rustup-init \
      "https://static.rust-lang.org/rustup/archive/$RUSTUP_VERSION/$target/rustup-init" \
 && echo "$sum  /tmp/rustup-init" | sha256sum -c - \
 && chmod +x /tmp/rustup-init \
 && /tmp/rustup-init -y --no-modify-path --profile minimal \
      --default-toolchain "$RUST_TOOLCHAIN" \
      --component rustfmt --component clippy --component llvm-tools-preview \
 && rm /tmp/rustup-init

RUN cargo install --locked "sqlx-cli@$SQLX_CLI_VERSION" \
      --no-default-features --features postgres,rustls \
 && cargo install --locked "cargo-deny@$CARGO_DENY_VERSION" \
 && cargo install --locked "cargo-llvm-cov@$CARGO_LLVM_COV_VERSION" \
 && cargo install --locked "cargo-mutants@$CARGO_MUTANTS_VERSION" \
 && rm -rf "$CARGO_HOME/registry" "$CARGO_HOME/git"

RUN git clone --filter=blob:none --no-checkout https://github.com/flutter/flutter.git /home/vscode/flutter \
 && git -C /home/vscode/flutter checkout --quiet "$FLUTTER_COMMIT" \
 && test "$(git -C /home/vscode/flutter describe --tags --exact-match)" = "$FLUTTER_VERSION" \
 && flutter config --no-analytics \
 && flutter precache --linux --web \
 && flutter --version
