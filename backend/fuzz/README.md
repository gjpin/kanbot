# Fuzz targets

[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets for code that
parses untrusted input (`backend/AGENTS.md` §4). They need a nightly
toolchain and are run manually, not in CI.

| Target | Input | Checks |
|---|---|---|
| `token` | any bytes as a bearer token | parsing and validation never panic, and refuse everything |
| `signed_claims` | any JSON as the claims of a correctly signed token | the claim checks never panic, and accept only tokens that meet every rule |
| `login_params` | the sign-in's parameters: the native redirect URI, the PKCE challenge, a one-time code or session token, the `Cookie` header | the parsers never panic, and accept only what they promise (the app's redirect or a loopback one, 43 base64url characters, the token's prefix and length, the named cookie) |
| `cedar_entities` | arbitrary facts and claims: groups, client ID, memberships, links, admins | building the Cedar entities and deciding every action never fails or panics; platform admins are allowed everything, a user with no memberships or admin rights nothing |

```sh
cargo install --locked cargo-fuzz@0.13.2
cd backend
cargo +nightly fuzz run token
cargo +nightly fuzz run signed_claims
cargo +nightly fuzz run login_params
cargo +nightly fuzz run cedar_entities
```

Last run on 2026-11-21 (nightly, cargo-fuzz 0.13.2): two minutes per target,
about 250,000 inputs each (36,000 for `cedar_entities`); nothing found.

They validate against the test-only keys in `tests/fixtures/oidc/`.
`corpus/` and `artifacts/` are git-ignored; commit a crashing input as a
regression test instead.
