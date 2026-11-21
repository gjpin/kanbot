# Development container

Everything needed to work on kanbot and run every check in
`backend/AGENTS.md` and `frontend/AGENTS.md`:

- Rust through rustup, with the toolchain of `backend/rust-toolchain.toml`
  (rustfmt, clippy, llvm-tools-preview), `sqlx-cli`, `cargo-deny`,
  `cargo-llvm-cov` and `cargo-mutants`, at the versions CI uses;
- Flutter (the version CI uses), with the Linux desktop and web artifacts;
- Docker, for `backend/compose.yaml`: Postgres and the local Authelia.

On creation it runs `backend/dev/auth-setup.sh`; on every start it runs
`docker compose up -d --wait` and `sqlx migrate run` in `backend/`. `auth.kanbot.internal` already
resolves to the container's loopback and `DATABASE_URL` is set, so the
checks run as `backend/AGENTS.md` lists them. To run the backend against the
stack: `cd backend && set -a && . dev/dev.env && set +a && cargo run`.

Use a checkout either from the container or from the host, not both:
`flutter pub get` writes absolute paths into `frontend/.dart_tool/`, and
Linux and macOS builds would keep rebuilding over each other in
`backend/target/`.

Fuzzing (`backend/fuzz/`) needs a nightly toolchain:
`rustup toolchain install nightly && cargo install cargo-fuzz`.

Pins: the base image by digest, rustup-init by checksum, Flutter by commit,
crates by version. Keep the versions in step with `.github/workflows/`.
