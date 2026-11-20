# Fuzz targets

[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets for code that
parses untrusted input (`backend/AGENTS.md` §4). They need a nightly
toolchain and are run manually, not in CI.

| Target | Input | Checks |
|---|---|---|
| `token` | any bytes as a bearer token | parsing and validation never panic, and refuse everything |
| `signed_claims` | any JSON as the claims of a correctly signed token | the claim checks never panic, and accept only tokens that meet every rule |

```sh
cargo install cargo-fuzz
cd backend
cargo +nightly fuzz run token
cargo +nightly fuzz run signed_claims
```

They validate against the test-only keys in `tests/fixtures/oidc/`.
`corpus/` and `artifacts/` are git-ignored; commit a crashing input as a
regression test instead.
