# AGENTS.md (backend)

Rules for `backend/`, a Rust HTTP API built on **axum**, **tokio**, **tower-http** and **sqlx** (PostgreSQL). These rules add to the [root `AGENTS.md`](../AGENTS.md). Follow both.

---

## Project structure

Code is organized **by feature first, then by layer** inside each feature:

```
backend/
├── openapi.json             # the API contract (generated, committed; the frontend's client is built from it)
├── openshell-api/           # the OpenShell gateway's gRPC API: vendored .proto files, generated code (its own crate), regenerate.sh
├── build.rs                 # rebuilds when a migration is added
├── compose.yaml             # local Postgres, Authelia and Keycloak; `--profile observability` adds collector + Grafana
├── dev/                     # local stack: auth-setup.sh, authelia/ and keycloak/ config and users, dev.env, policies.cedar; .generated/ is git-ignored
├── otel-collector/          # collector config for local development (filters, limits)
├── migrations/              # sqlx migrations, one file per change
├── .sqlx/                   # offline query metadata from `cargo sqlx prepare` (committed)
├── src/
│   ├── main.rs              # thin binary: tracing, arguments, config, runtime → kanbot_backend::{run, migrate}
│   ├── bin/openapi.rs       # writes the OpenAPI document (openapi.json)
│   ├── lib.rs               # module list, run(), migrate(), graceful shutdown
│   ├── cli.rs               # command-line arguments (`migrate`)
│   ├── config.rs            # Config from environment variables
│   ├── db.rs                # PgPool construction (limits and timeouts), MIGRATOR, readiness check
│   ├── state.rs             # AppState, cloned into every handler
│   ├── telemetry.rs         # OpenTelemetry setup: OTLP exporters, tracing subscriber
│   ├── telemetry_relay/     # /telemetry/v1/*: forwards the app's OTLP telemetry to the collector
│   ├── error.rs             # AppError (IntoResponse) and StartupError
│   ├── http/
│   │   ├── mod.rs           # router() and openapi(): merges feature routes, middleware stack
│   │   ├── health.rs        # /health and /ready
│   │   ├── problem.rs       # RFC 9457 problem details, ErrorCode
│   │   ├── web.rs           # serving the Flutter web build (WEB_DIR) and its Content-Security-Policy
│   │   ├── client_ip.rs     # client address behind trusted proxies (X-Forwarded-For)
│   │   ├── middleware/      # cross-cutting middleware (request telemetry, security headers, rate limit, ...)
│   │   └── extract.rs       # shared custom extractors (AuthUser, RequireAdmin)
│   ├── auth/                # OIDC: config, discovery, JWKS key cache, access-token validation, authentication middleware
│   ├── users/               # users table (upserted on each authenticated request), /me
│   ├── sessions/            # kanbot sessions: /auth/* login flow, native handoff, IdP token refresh, cleanup
│   ├── authz/               # Cedar authorization: schema, built-in and deployer policies, require()/can()/visible_*()
│   ├── organizations/       # /organizations: organizations, their admins and team links
│   ├── teams/               # /teams: teams, members and maintainers, IdP group sync
│   ├── audit/               # the audit log of changes to organizations and teams, GET /audit
│   ├── names.rs             # slugs and names of organizations and teams
│   ├── openshell/           # OpenShell integration: config, gateway client, tokens, workspace links and membership sync
│   └── <feature>/           # e.g. boards/, cards/
│       ├── mod.rs           # pub fn routes() -> OpenApiRouter<AppState>
│       ├── model.rs         # domain types: validated newtypes and entities
│       ├── dto.rs           # request/response types (serde), converted to/from model types
│       ├── handlers.rs      # axum handlers
│       ├── service.rs       # business rules
│       └── repo.rs          # database access
├── tests/
│   ├── common/mod.rs        # shared test setup (test app over a #[sqlx::test] pool); `pub mod common;` in each test file
│   ├── common/idp.rs        # test IdP: discovery, a changeable JWKS, token signing (§4a)
│   ├── common/authelia.rs   # programmatic login at the local Authelia (§4a)
│   ├── common/keycloak.rs   # programmatic login at the local Keycloak (§4a)
│   ├── fixtures/            # test-only migrations
│   ├── fixtures/oidc/       # committed test-only signing keys (§4a)
│   ├── authelia.rs          # end-to-end tests against the local Authelia
│   ├── keycloak.rs          # end-to-end tests against the local Keycloak
│   └── <feature>.rs         # HTTP-level integration tests, one file per feature
├── examples/dev_token.rs    # `cargo run --example dev-token -- alice`: a local Authelia access token
├── benches/                 # criterion benchmarks
└── fuzz/                    # cargo-fuzz targets (own crate and lockfile; nightly, run manually; see fuzz/README.md)
```

Create `http/extract.rs`, `benches/` and `fuzz/` only when there is something to put in them.

Authentication and authorization are being built in phases, following [`docs/plan/auth.md`](../docs/plan/auth.md). Phases 2 (bearer tokens), 3 (sessions) and 4 (authorization) are implemented.

### Layering rules

Dependencies point one way: `handlers` → `service` → `repo`. `model` is used by all three. A layer never imports from a layer above it.

| Module | May | Must not |
|---|---|---|
| `handlers.rs` | Use axum extractors, call `service`, convert between `dto` and `model` | Contain SQL, call `repo` directly, contain business rules |
| `service.rs` | Enforce business rules, call `repo`, take and return `model` types | Import `axum`, `http` or `dto` types |
| `repo.rs` | Run `sqlx::query!`-family macros, map rows to `model` types | Contain business rules, return `dto` types or raw rows |
| `model.rs` | Define newtypes with validating constructors and domain errors | Depend on `axum`, `sqlx` or `serde` request types |
| `dto.rs` | Define `Deserialize`/`Serialize` types with `deny_unknown_fields` | Be used outside `handlers.rs` |

Other rules:

- **A new feature** gets its own directory with the files above, and its `routes()` is merged in `http::api`. Do not put feature code in `http/`, `lib.rs` or another feature's directory.
- **Cross-feature calls** go through the other feature's `service`, never its `repo`.
- **`main.rs` stays thin.** All logic lives in the library crate so that integration tests can build the app.
- **No catch-all modules** such as `utils.rs`, `helpers.rs` or `common.rs` in `src/`. Code that is shared across features goes into a module named for what it does.
- **Keep files small.** Split a file once it holds more than one responsibility or grows past about 300 lines.

---

## 1. Hard rules

### 1.1 No `unsafe`

- `unsafe` is forbidden. `#![forbid(unsafe_code)]` is set in `src/main.rs` and `src/lib.rs`, and `unsafe_code = "forbid"` is set in `Cargo.toml`. A forbidden lint cannot be overridden by an attribute.
- Do not add dependencies whose purpose is to let you run unsafe code on this crate's behalf.

### 1.2 No panics in production code

These are all **denied** by Clippy outside tests:

| Forbidden                                           | Use instead                                                                                                           |
| --------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `.unwrap()`, `.expect(..)`                          | `?` with an error type, `.ok_or(..)?`, `match`, `if let`, `.unwrap_or(..)`, `.unwrap_or_default()`                    |
| `panic!`, `todo!`, `unimplemented!`, `unreachable!` | Return an error, or design types so the case cannot exist                                                             |
| `v[i]`, `&v[a..b]`                                  | `v.get(i)`, `v.get(a..b)`, iterators, `split_first`, pattern matching                                                 |
| `&s[..n]` on strings                                | `s.get(..n)`, `s.chars()`, `s.char_indices()`                                                                         |
| `a + b`, `a * b`, `a - b` on integers               | `checked_add` / `checked_mul` / `checked_sub` (return an error on `None`), or `saturating_*` when clamping is correct |
| `x as u32`                                          | `u32::try_from(x)?`, or `From`/`Into` when the conversion cannot fail                                                 |
| `dbg!`, `println!`, `eprintln!`                     | `tracing::{debug, info, warn, error}!`                                                                                |
| `std::process::exit`                                | Return `Err` from `main`                                                                                              |
| Holding a `Mutex`/`RwLock` guard across `.await`    | Drop the guard before awaiting, or use `tokio::sync::Mutex`                                                           |
| Ignoring a `#[must_use]` value                      | Handle it, or propagate it with `?`                                                                                   |

**Request handlers in particular** must never panic. Every axum handler returns `Result<impl IntoResponse, AppError>` (or similar), and all errors go through `AppError`, which maps them to an HTTP status and a problem details body (§2). Do not leak internal error details (SQL errors, stack traces, file paths) in response bodies. Log them with `tracing`; the client gets only the error code.

Tests (`#[test]`, `#[cfg(test)]`) may use `unwrap`, `expect`, `panic!`, indexing, `dbg!` and `println!`. This is configured in `clippy.toml`.

### 1.3 Do not turn the lints off

- **Never** write `#[allow(...)]` or `#![allow(...)]`. Clippy denies `allow_attributes`.
- **Never** weaken lints through `cfg_attr`, `RUSTFLAGS`, `.cargo/config.toml`, `build.rs`, `--cap-lints`, or by editing `[lints]` in `Cargo.toml`, `clippy.toml` or `deny.toml`.
- The only accepted way to silence a lint is `#[expect(lint_name, reason = "...")]`, on the **smallest possible item**, with a specific reason. Clippy denies `allow_attributes_without_reason`. Every `#[expect` needs human approval (see [Exceptions](#exceptions)).
- `#[expect]` fails the build if the lint stops firing, so stale exceptions are caught. Do not replace it with `allow`.

---

## 2. Use the type system for correctness

- **SQL:** use only the compile-time checked macros `sqlx::query!`, `sqlx::query_as!` and `sqlx::query_scalar!`. Never build SQL with `format!` or string concatenation. Never use the unchecked `sqlx::query(..)`/`query_as(..)` functions with dynamic strings. After changing a query, run `cargo sqlx prepare` and commit the updated `.sqlx/` directory, because CI builds with `SQLX_OFFLINE=true`.
- **Migrations:** put schema changes in `migrations/` as new files (`sqlx migrate add <name>`). Never edit, rename or delete a migration that has already been committed; CI rejects pull requests that do. Fix a mistake with a new migration.
  - Migrations run as a deploy step, `kanbot-backend migrate`, never at server startup, so the server's database role does not need DDL rights. `migrate` uses one connection with no statement timeout but a 5 s lock timeout, so it cannot stall the app behind a table lock.
  - `/ready` returns `503` until every migration is applied with a matching checksum and none is half-applied. Deploy order: `migrate`, then the new version.
  - Write migrations that the *previous* version of the app can run against (expand, then contract in a later release): during a deploy, old instances keep serving on the new schema.
- **Validated newtypes:** domain values are newtypes with private fields, built only through a validating constructor, for example:

  ```rust
  pub struct Email(String);
  impl Email {
      pub fn parse(raw: &str) -> Result<Self, ValidationError> { /* validate */ }
      pub fn as_str(&self) -> &str { &self.0 }
  }
  ```

  Use `UserId(Uuid)`, `BoardId(Uuid)`, `Email(String)` and so on. Business logic takes newtypes, never raw `String`/`Uuid`/`i64`. Parse and validate at the edge (the handler or extractor), then pass validated types inward.
- **Request bodies:** every `Deserialize` type used for input has `#[serde(deny_unknown_fields)]`.
- **Secrets:** passwords, tokens, API keys and connection strings are `secrecy::SecretString` (or `SecretBox<T>`). Never derive `Debug`/`Serialize` on a type that holds a secret in plain form, and never log `.expose_secret()`. Call `.expose_secret()` only at the exact point of use.
- **Errors:** use `thiserror` enums. One `AppError` implements `IntoResponse`. Do not use `Box<dyn Error>` in handler or domain code.
- **Error responses** are RFC 9457 problem details (`application/problem+json`, `src/http/problem.rs`) with a stable `code` (`ErrorCode`) and, for `422`, `errors: [{pointer, code}]` (JSON Pointer to the field, plus a `snake_case` reason). Rules:
  - Never put free-form text in a problem: no `detail`, no echo of the input, no messages from libraries or the database. Clients map `code` to their own messages.
  - `ErrorCode` strings are a public contract: add codes, never rename or reuse one. Field error codes (`too_long`, `required`, ...) are just as stable.
  - Return `AppError`; do not build error responses by hand. The `ensure_problem_body` layer converts any other error response (axum rejections, 404/405, body limit, timeout, panic) into a problem for its status, keeping headers such as `Allow`. Keep it inside `CorsLayer` so browsers can read error bodies.
  - Each new `AppError` variant gets a test of its status and code.

## 2a. The API contract (OpenAPI)

`backend/openapi.json` is the contract between backend and frontend; the frontend's client is generated from it.

- Every route is registered through `utoipa_axum` (`OpenApiRouter::routes(routes!(handler))`) and every handler has a `#[utoipa::path(...)]` with its tag, request body and **all** its responses, including error responses as `body = Problem, content_type = "application/problem+json"`. Never add a route with plain `Router::route`: it would be missing from the contract. The one exception is the telemetry relay (`telemetry_relay/`), whose contract is the OTLP/HTTP specification.
- Request and response types (`dto.rs`) derive `utoipa::ToSchema` next to `Serialize`/`Deserialize`. Doc comments become the descriptions.
- After changing a route or a type, run `cargo run --bin openapi -- openapi.json` from `backend/`, then regenerate the frontend client (`frontend/AGENTS.md` §3), and commit all of it. `tests/openapi.rs` fails while the committed document is stale.
- Breaking changes (removing or renaming a field or route, adding a required request field, changing a type) break app versions already installed. Add instead, and remove only once no supported app version uses it.

## 3. Runtime guardrails

`src/http/mod.rs` and `src/db.rs` install these. Keep them in place, and do not remove or loosen them without approval:

- Request telemetry (`http/middleware/telemetry.rs`), outermost: a server span per request that continues the caller's W3C trace, plus the `http.server.request.duration` and `http.server.active_requests` metrics (§3a).
- `CatchPanicLayer`: a panic in one request returns a 500 and does not kill the server. Because of this, `panic = "abort"` must **not** be set in any profile.
- `TimeoutLayer`: a request timeout. A timed-out request gets a 503.
- `CorsLayer`: cross-origin requests are allowed only from the origins listed in `CORS_ALLOWED_ORIGINS`. Never allow `*`.
- Security headers (`http/middleware/security_headers.rs`): every response carries `Cache-Control: no-store`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, `Strict-Transport-Security` and `X-Content-Type-Options: nosniff`. A handler may set its own `Cache-Control` for a response that is safe to cache; the layer keeps it.
- `SetSensitiveHeadersLayer`: `Authorization`, `Cookie` and `Set-Cookie` are marked sensitive so that logs and traces never record them. Add any new credential-carrying header to `SENSITIVE_HEADERS`.
- `RequestBodyLimitLayer` + `DefaultBodyLimit`: a body size limit.
- Database pool: `max_connections`, `acquire_timeout` and a PostgreSQL `statement_timeout`.

- Per-client rate limiting (`http/middleware/rate_limit.rs`, `tower_governor`), keyed by client IP (`http/client_ip.rs`): `X-Forwarded-For` is read only from `TRUSTED_PROXIES`, so clients cannot choose their own key. The server must keep serving with `into_make_service_with_connect_info`; without it, requests fail closed (`500`). Applied to every route.
- Per-user rate limiting (`rate_limit::limit_per_user`, `governor`'s keyed limiter by user ID), inside the authentication middleware. Applied to every route (`RATE_LIMIT_USER_*`), and to the telemetry relay (`RATE_LIMIT_TELEMETRY_*`).
- Failed-authentication limiting (`auth/middleware.rs`, `auth/failures.rs`), per client IP: every refused credential (`401`) spends budget; a client over budget gets `429` for any request with credentials, before they are checked. It is a small GCRA of its own because `governor` cannot check a key without spending budget.
- Load shedding: a global cap on requests in flight (`tower` `GlobalConcurrencyLimit` + `LoadShed`; a plain `ConcurrencyLimit` added with `Router::layer` would cap each route separately). Above it, requests get `503` with `Retry-After`.

### Rate limits

The defaults are sized for a 10,000-employee company where everyone may reach kanbot through one corporate IP: about 1,000 requests/s at peak (30% active, roughly 0.3 requests/s each). Every value is configurable.

| Limit | Variable(s) | Default |
|---|---|---|
| Per client IP, all requests | `RATE_LIMIT_IP_PER_SECOND`, `RATE_LIMIT_IP_BURST` | 2000/s, burst 4000 |
| Per client IP, failed authentications (401) | `RATE_LIMIT_AUTH_FAILURE_PER_SECOND`, `RATE_LIMIT_AUTH_FAILURE_BURST` | 50/s, burst 500 |
| Per client IP, sign-in routes (`/auth/login`, `/auth/callback`, `/auth/token`) | `RATE_LIMIT_LOGIN_PER_SECOND`, `RATE_LIMIT_LOGIN_BURST` | 100/s, burst 500 |
| Per user | `RATE_LIMIT_USER_PER_SECOND`, `RATE_LIMIT_USER_BURST` | 20/s, burst 100 |
| Per user, telemetry relay | `RATE_LIMIT_TELEMETRY_PER_SECOND`, `RATE_LIMIT_TELEMETRY_BURST` | 1/s, burst 20 |
| Requests in flight per instance | `MAX_IN_FLIGHT_REQUESTS` | 512 (then `503` with `Retry-After`) |
| Database pool per instance | `DATABASE_MAX_CONNECTIONS` | 10 |

- Limits are kept in memory per server instance, so N instances allow N times the traffic. Say so wherever deployment is documented.
- IPv6 clients are keyed by their **/64** prefix, IPv4 clients by their full address.
- Client IPs come from `http/client_ip.rs`, so `TRUSTED_PROXIES` applies.
- The failed-authentication limiter is checked before credentials are validated. The per-user limiter runs after authentication, keyed by the user ID.
- Rejections are `429 rate_limited` problems with `Retry-After`.
- A rate limit of zero, or one that is not a number, is a startup error.

Every outbound call (HTTP or database) must have a timeout. Never spawn unbounded work per request.

### Configuration

All from environment variables (`src/config.rs`, `src/auth/config.rs`, `src/telemetry.rs`). Invalid values stop the server at startup; it never falls back to a default for a value that was set. The phase column refers to the [`docs/plan/auth.md`](../docs/plan/auth.md) phase that added each variable.

| Variable | Phase | Default | Meaning |
|---|---|---|---|
| `DATABASE_URL` | | required | PostgreSQL connection string (secret) |
| `DATABASE_MAX_CONNECTIONS` | 2 | `10` | Pool size per instance |
| `LISTEN_ADDR` | | `127.0.0.1:3000` | HTTP listen address |
| `CORS_ALLOWED_ORIGINS` | | none | Browser origins allowed cross-origin, comma-separated. Optional when the backend serves the web build (`WEB_DIR`) |
| `TRUSTED_PROXIES` | | none | Reverse proxies (IPs, CIDRs) whose `X-Forwarded-For` is trusted |
| `TELEMETRY_RELAY_UPSTREAM` | | unset (relay off) | OTLP/HTTP collector the app's telemetry is relayed to |
| `OTEL_*` | | SDK defaults | OpenTelemetry SDK settings (§3a) |
| `RUST_LOG` | | `info` | Log and span filter |
| `OIDC_ISSUER` | 2 | required | Must equal the tokens' `iss` and the discovery document's `issuer` exactly. HTTPS only |
| `OIDC_AUDIENCE` | 2 | required | Accepted access-token audience, for example `kanbot-api` |
| `OIDC_ROLES_CLAIM` | 2 | required | Dot path to the roles array (`groups`, `roles`, `realm_access.roles`) |
| `OIDC_ADMIN_ROLE` | 2 | required | Role that grants platform admin, for example `kanbot-admin`. Must not be empty |
| `OIDC_USER_ROLE` | 2 | required | Role that grants access, for example `kanbot-user`. Must not be empty |
| `OIDC_SUBJECT_CLAIM` | 2 | `sub` | Claim that identifies the user. `oid` for Entra ID |
| `OIDC_ALLOWED_CLIENTS` | 2 | any | Comma-separated client IDs, matched against `azp`, then `client_id`, then `cid`. Must not contain `OIDC_AUDIENCE` |
| `OIDC_JWKS_TTL` | 2 | `3600` | Seconds between JWKS refreshes |
| `OIDC_JWKS_ALLOWED_ORIGINS` | 2 | none | Extra HTTPS origins allowed to serve the JWKS |
| `OIDC_CA_FILE` | 2 | none | PEM bundle trusted for the IdP, in addition to the system roots |
| `OIDC_DANGEROUSLY_ALLOW_INSECURE_HTTP` | 2 | `false` | Allows `http://` issuers on numeric loopback hosts only. Development and tests only |
| `RATE_LIMIT_*`, `MAX_IN_FLIGHT_REQUESTS` | 2, 3 | see [Rate limits](#rate-limits) | |
| `OIDC_CLIENT_ID` | 3 | required | Kanbot's confidential client. Must differ from `OIDC_AUDIENCE` |
| `OIDC_CLIENT_SECRET` / `OIDC_CLIENT_SECRET_FILE` | 3 | one required | Its secret (`SecretString`) |
| `OIDC_SCOPES` | 3 | `openid profile email offline_access` | Add what the IdP needs for the roles claim, for example `groups` |
| `PUBLIC_URL` | 3 | required | External base URL, for example `https://kanbot.example.com`. Used for the callback URL, cookie checks and CSRF origin checks |
| `SESSION_ENCRYPTION_KEYS` / `SESSION_ENCRYPTION_KEYS_FILE` | 3 | one required | Comma-separated base64 keys, each with a key ID (secret). The first encrypts and all decrypt, so keys can be rotated |
| `SESSION_IDLE_TIMEOUT` | 3 | `7d` | A session ends after this long without use |
| `SESSION_ABSOLUTE_TIMEOUT` | 3 | `30d` | A session ends after this long regardless. Sessions also end when the IdP refuses a refresh |
| `WEB_DIR` | 3 | unset (off) | Directory with the Flutter web build to serve at `/` |
| `OIDC_GROUPS_CLAIM` | 4 | value of `OIDC_ROLES_CLAIM` | Dot path to the groups array used for team sync and Cedar `principal.groups` |
| `AUTHZ_POLICY_FILE` | 4 | none | Deployer Cedar policies. `forbid` only: a file containing any `permit` stops startup |
| `OPENSHELL_GATEWAY_URL` | 7 | unset (off) | The OpenShell gateway's gRPC endpoint. HTTPS only (`http` on a numeric loopback host with `OPENSHELL_DANGEROUSLY_ALLOW_INSECURE_HTTP=true`, tests only) |
| `OPENSHELL_AUDIENCE` | 7 | required with the gateway | Audience of the gateway's tokens, for example `openshell-gateway`. Must differ from `OIDC_AUDIENCE` |
| `OPENSHELL_CLIENT_ID`, `OPENSHELL_CLIENT_SECRET` / `OPENSHELL_CLIENT_SECRET_FILE` | 7 | required with the gateway | Kanbot's client for OpenShell tokens (secret) |
| `OPENSHELL_TOKEN_SCOPE` | 7 | none | `scope` to request for the gateway's audience, if the identity provider needs one |
| `OPENSHELL_TOKEN_EXCHANGE` | 7 | `false` | Exchange the user's token (RFC 8693) for calls a user starts |
| `OPENSHELL_CA_FILE` | 7 | none | PEM certificates trusted for the gateway, in addition to the system roots |

## 3a. Observability (OpenTelemetry)

Traces, logs and metrics are OpenTelemetry, exported over OTLP/HTTP (protobuf) to a collector (`src/telemetry.rs`). The SDK reads the standard `OTEL_*` variables (`OTEL_EXPORTER_OTLP_ENDPOINT`, default `http://localhost:4318`; `OTEL_EXPORTER_OTLP_HEADERS`, which may carry credentials and must never be logged; `OTEL_SERVICE_NAME`, default `kanbot-backend`; `OTEL_RESOURCE_ATTRIBUTES`; `OTEL_TRACES_SAMPLER`). `OTEL_SDK_DISABLED=true` turns export off. Logs also go to stdout.

- **Instrument with `tracing`.** Spans become OpenTelemetry spans and events become OpenTelemetry logs, correlated with the active span. Never use another logging or tracing API.
- **Every request already has a server span** (method, route template, path, status). Add child spans with `#[tracing::instrument(skip_all, fields(...))]` on service and repo functions worth timing; `skip_all` so arguments are never recorded by accident.
- **Never record** secrets, tokens, `Authorization` or cookie values, request or response bodies, query strings, emails or other personal data, in span fields, events or metric attributes. Record identifiers (`board.id`) instead.
- **Metrics** use the global meter (`opentelemetry::global::meter(telemetry::SCOPE)`), created after `Telemetry::init`. Follow the OpenTelemetry semantic conventions for names and units, and keep attribute values bounded: route templates, never raw paths, user ids or free text.
- **Numbers in span fields** are recorded as `i64` (or `f64`): `tracing-opentelemetry` records unsigned integers as strings.
- Problem bodies carry the request's `trace_id`, so a user's error report leads to its trace and logs.
- `tests/telemetry.rs` asserts on spans, logs and metrics with the SDK's in-memory exporters (`opentelemetry_sdk` `testing` feature). Instrumentation changes need tests there too.

### The telemetry relay

The app cannot hold collector credentials, so it sends OTLP to the API at `/telemetry/v1/{traces,logs,metrics}` (`src/telemetry_relay/`), which forwards it to `TELEMETRY_RELAY_UPSTREAM`. Only authenticated users who have opted in may use it (`users.telemetry_opt_in`, default `false`, set through `PUT /me/preferences`): no user is `401`, no consent is `403 telemetry_disabled`. It never adds the user's identity to what it forwards. Keep its protections (body limit `MAX_BODY_BYTES`, protobuf/JSON only, no compressed bodies, no client headers forwarded, per-user rate limit `RATE_LIMIT_TELEMETRY_*`). The collector must still filter what it accepts; `otel-collector/otelcol-config.yaml` shows the minimum (memory limiter, only our service names).

## 3b. Authentication and security invariants

Users sign in at an external OIDC IdP; kanbot has no passwords or local accounts. The design, and the IdP requirements and setup guides, are in [`docs/oidc.md`](../docs/oidc.md). An API request is authenticated in one of two ways, and both resolve to the same validated user and roles:

1. **An IdP JWT access token** in `Authorization: Bearer`, validated locally against the IdP's JWKS (CLI, scripts, CI, agents, other services).
2. **A kanbot session**, for kanbot's own apps (`sessions/`): the `__Host-kanbot_session` cookie on web, a `kbs_` bearer token on native. The backend runs the login flow as the confidential client (`/auth/login`, `/auth/callback`, and `/auth/token` for the native one-time code), keeps the IdP tokens server-side sealed with XChaCha20-Poly1305 (`sessions/crypto.rs`, row and field bound, key ID for rotation), refreshes them under a row lock, and checks the stored access token with exactly the rules used for bearer tokens. A stale session *cookie* makes the request anonymous and is cleared; a bad `kbs_` bearer is a `401`.

These rules hold in every change:

- **Secure by default.** Every route requires authentication except an explicit public list: `/health`, `/ready`, `/auth/login`, `/auth/callback`, `/auth/token`, `/auth/config` and the web build's static files (`http/web.rs`). Protected operations declare both security schemes, `bearer` and `session`. A test walks every operation in `http::openapi()`, plus the telemetry relay routes, and fails for any route that is neither on the list nor returns `401` without credentials. Adding a public route means adding it to that list on purpose.
- **Never log, trace or put in metrics:** tokens, codes, cookies, the client secret or session keys; raw claims other than issuer, subject ID and client ID; display names or emails. Record internal IDs (`user.id`) instead.
- **Database errors** are logged as the error kind, SQLSTATE and constraint name only. Postgres error details can contain row values (`Key (subject)=(...) already exists`).
- **Auth failures return stable problem codes only**, never the reason. `401` responses carry `WWW-Authenticate: Bearer error="invalid_token"` (RFC 6750) when a bearer token was presented, and plain `WWW-Authenticate: Bearer` when none was. The reason goes only into the bounded `reason` attribute of the `kanbot.auth.token.rejections` metric.
- **Invalid credentials are a `401`**, never treated as anonymous. Until the IdP's keys have loaded, authenticated requests get `503 unavailable`, not `401`.
- **Outbound calls** (IdP discovery, JWKS, token endpoint) have connect and total timeouts, do not follow redirects, and cap how many response bytes they read.
- **CSRF:** a state-changing request authenticated by the session cookie needs `Origin` equal to `PUBLIC_URL`'s origin and `X-Kanbot-CSRF: 1`, else `403`. Bearer requests are exempt.
- **Cookies** are `__Host-` (`Secure`, `Path=/`, no `Domain`) and `HttpOnly`: the session is `SameSite=Strict`, the login binding `SameSite=Lax` (it must survive the IdP's redirect).
- **Randomness:** every token, code, state and nonce is 32 bytes from `getrandom` (`sessions/secrets.rs`); never `rand`. Secrets are compared by looking up their SHA-256 hash in the database, never by comparing strings in memory.
- **Authorization** is decided by the `authz` module with Cedar (§3c). Never write an ad hoc role check in a handler or service.

## 3c. Authorization

The model, the built-in permissions and the deployer policy guide are in [`docs/authorization.md`](../docs/authorization.md). Grants are data (organizations, teams, links, admins); the built-in `permit` policies (`src/authz/policies.cedar`, schema `src/authz/schema.cedarschema`) turn them into access, and deployers can add only `forbid` policies (`AUTHZ_POLICY_FILE`).

- **Every feature that touches organization data calls `authz`**, in its service, before it reads or changes anything:
  - `authz::service::require(db, policies, actor, action, resource)` before an operation. It returns the decision (its policy IDs go to the audit log), `403` when the actor may see the resource but not do this, and `404` when they may not even see it.
  - `authz::service::decisions` (or `can`) to tell the app what the caller may do; responses list it as `permissions`.
  - `authz::service::visible_organizations` / `visible_teams` for lists.
  Handlers get the actor with the `Caller` extractor (`http/extract.rs`): the user, how they authenticated (`via`) and their address.
- **Changes are audited**: a service that changes organizations or teams records an `audit::model::NewEntry` with `audit::service::record` in the same transaction. Details hold IDs and enumerated values only.
- **New features** that belong to an organization use the `read` and `write` actions on it. A new kind of permission is a new action in the schema, a built-in policy and `authz::model::Action`, with tests of what it allows and denies (`src/authz/policies/tests.rs`).
- **Never add a `permit` outside `policies.cedar`**, and never let deployer policies contain one: `visible_*` pre-filters with SQL for the built-in permits, which is correct only because deployer policies can only remove access. `tests/authz.rs` checks the pre-filter against Cedar for random data.
- Entities are loaded per decision (`authz/repo.rs`): only the actor's teams and the resources asked about. Keep it that way; do not cache decisions across requests.

## 4. Testing tools

- Use `proptest` for pure logic (parsers, validation, state transitions, arithmetic).
- Anything that parses untrusted input should get a `cargo-fuzz` target under `fuzz/`. Fuzzing needs nightly and is run manually, not in CI.
- CI runs `cargo mutants` on changed code. A missed mutant must be fixed with a better test.
- CI enforces a minimum line coverage with `cargo llvm-cov`. Do not lower the threshold.

## 4a. Testing authentication

- **Test IdP** (`tests/common/idp.rs`): an axum server on `127.0.0.1:0` that serves discovery and a JWKS that tests can change at runtime (rotate, empty, broken, oversized, redirect, slow), counts the requests it gets, and signs tokens with any claims and header. The app under test reaches it through `OIDC_DANGEROUSLY_ALLOW_INSECURE_HTTP`. Use it for token validation, key cache and discovery tests; do not stub the validator.
- **Fixture keys** (`tests/fixtures/oidc/`): committed signing keys for **tests only** (RSA-2048 keys A and B for rotation, an RSA-1024 key that must be rejected, P-256, P-384 and Ed25519 keys, and their public JWKs). Its README says so and lists the `openssl` commands that generated them. Never use them outside tests, and never put any other key there. A secret scanner needs an allowlist for this folder.
- **Local Authelia** (`tests/authelia.rs`): end-to-end tests with real tokens from the local Authelia (`dev/authelia/configuration.yml`), obtained by the programmatic login helper `tests/common/authelia.rs`, which `examples/dev_token.rs` shares through `#[path]`. The dev users are in `dev/authelia/users_database.yml`, each with the documented dev-only password `<username>-dev-password`: `alice` (`kanbot-admin`), `bob` (`kanbot-user`), `carol` (no kanbot group) and `dave` (`kanbot-user` and `contractors`). The `kanbot` client's dev-only secret is `kanbot-dev-client-secret`.
- **Local Keycloak** (`tests/keycloak.rs`): the second identity provider, with the same dev users and client secret (`dev/keycloak/kanbot-realm.json`), at `https://auth.kanbot.internal:8443/realms/kanbot`. `tests/common/keycloak.rs` signs in through Keycloak's login form.
- Database, Authelia and Keycloak tests **fail rather than skip** when their service is missing.

### Generated gRPC code

`openshell-api/` holds the OpenShell gateway's API, generated from vendored `.proto` files. Generated code carries `allow` attributes and does not meet §1, so it is a crate of its own, outside these lints; everything in `src/` that calls it meets them. Never edit `openshell-api/src/generated/`: update the `.proto` files and run `sh openshell-api/regenerate.sh` (its README). CI fails if the generated code is stale.

## 5. Supply chain

- `cargo deny check` blocks known vulnerabilities, yanked crates, disallowed licenses, unknown registries and git dependencies.
- The toolchain is pinned in `rust-toolchain.toml`. `Cargo.lock` is committed.
- Outbound HTTPS (the OTLP exporter, the relay) uses `reqwest` with `native-tls` (OpenSSL on Linux, so builds need its headers). The rustls stack pulls in `webpki-root-certs` (CDLA-Permissive-2.0), which `deny.toml` does not allow. `opentelemetry-otlp` gets TLS through the shared `reqwest` dependency, so keep its `native-tls` feature.

## 6. Performance

Release builds keep `overflow-checks = true`. If you believe a safety rule costs too much performance, prove it with a `criterion` benchmark under `benches/` showing the before and after numbers, then ask for an exception. Never claim something is too slow without a measurement.

---

## Exceptions

Follow the exception steps in the root `AGENTS.md`. In this crate:

- The exception form is `#[expect(lint, reason = "...")]`. The reason should explain why the code is correct (for example `reason = "index is bounds-checked by the loop condition above"`), not just "needed".

## Before you finish: run these from `backend/`, all must pass

The tests need PostgreSQL, the local Authelia and the local Keycloak (§4a). Database tests use `#[sqlx::test]`, which creates a fresh database per test on the server at `DATABASE_URL`, applies `migrations/`, and drops it afterwards. They fail, rather than skip, when `DATABASE_URL` is not set. Never share data between tests through a common database.

Authelia runs at `https://auth.kanbot.internal:9443`. It refuses special-use domains such as `localhost`, so the name has to resolve to loopback: add this line to `/etc/hosts` once per machine:

```
127.0.0.1 auth.kanbot.internal
```

`dev/auth-setup.sh` (POSIX shell and `openssl`) generates a local CA, Authelia's certificate, secrets and OIDC signing key into the git-ignored `dev/.generated/`. It is idempotent, so run it every time. To run the backend itself against the local stack, load `dev/dev.env` (`set -a; . dev/dev.env; set +a`), and get a token for `curl` with `cargo run --example dev-token -- alice`. With `--sign-in <url>`, the same example plays the system browser for a native app's sign-in (the frontend's Linux end-to-end test uses it).

```sh
sh dev/auth-setup.sh
docker compose up -d --wait   # Postgres, Authelia and Keycloak
export DATABASE_URL=postgres://kanbot:kanbot@127.0.0.1:5432/kanbot
sqlx migrate run       # the SQL macros check queries against this database

cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo deny check
cargo sqlx prepare --check -- --all-targets --all-features   # needs sqlx-cli
```

`cargo test` includes `tests/openapi.rs`: after an API change, regenerate `backend/openapi.json` (§2a).
