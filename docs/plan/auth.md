# Authentication and authorization: implementation plan

This is the agreed plan for adding authentication (OIDC) and authorization
(organizations, teams, Cedar) to kanbot. It was worked out with the project owner
on 2026-11-20. It is written for the agent that implements it, who will not have
the original conversation. Everything decided is recorded here.

## How to use this plan

1. Read the root [`AGENTS.md`](../../AGENTS.md), [`backend/AGENTS.md`](../../backend/AGENTS.md),
   [`frontend/AGENTS.md`](../../frontend/AGENTS.md) and [`docs/oidc.md`](../oidc.md) first.
   Their rules always apply: never weaken a check, ask before any dependency not
   listed as approved below, and pin versions as `AGENTS.md` §2.1 says.
2. Work on the branch `auth/oidc` (already created from the `bootstrap` commit on
   `main`). Do the phases in order. Make each numbered step one commit, with every
   check of the touched directories passing.
3. When a step says **(verify)**, check the fact against the official
   documentation or by testing before relying on it. If it turns out false, stop
   and ask the human.
4. When a decision here turns out to be impossible or clearly wrong, stop and ask.
   Do not improvise around it.
5. Tick the checkboxes in [Progress](#progress) as steps land, and keep
   `docs/oidc.md` and both `AGENTS.md` files in sync with what is implemented.

## Current state

- `main` has the commit `bootstrap`: backend and frontend scaffolding, CI, and no
  features, users or auth.
- On `auth/oidc`, **not yet committed**: `docs/oidc.md` (the OIDC design and the
  IdP setup guides) and a `README.md` change that links it. Both are committed in
  phase 1.
- `docs/oidc.md` is marked "design, not implemented". Turn each section into
  current documentation as it is implemented.

## Decisions

### Identity

- **OIDC only.** Kanbot has no passwords or local accounts. Users sign in at an
  external IdP.
- **Kanbot is self-hosted.** Every deployment has its own domain and its own IdP.
  The project owner controls neither, so nothing may depend on a domain the
  project owns (no Universal Links or App Links for login).
- **Supported IdPs:** Keycloak, Authelia, Okta (custom authorization server),
  Microsoft Entra ID (single tenant, v2 tokens).
  - authentik is pending: its access-token `aud` cannot be set apart from the
    client ID.
  - Google, Apple, GitHub and any IdP with opaque access tokens are out of scope.
  - Requirements and per-IdP setup are in `docs/oidc.md`.
- **Two ways to authenticate an API request:**
  1. **IdP JWT access token** in `Authorization: Bearer`, for the CLI, scripts,
     CI, agents and other services. The API validates it locally against the
     IdP's JWKS: the same model as NVIDIA OpenShell.
  2. **Kanbot session**, for kanbot's own web and native apps. The backend runs
     the OIDC login as the deployment's single **confidential client**, keeps the
     IdP tokens server-side (encrypted), and gives the app an opaque session
     token: an `HttpOnly` cookie on web, a bearer token on native.

  Both resolve to the same validated user and roles. For a session, the backend
  checks the stored IdP access token with exactly the rules used for bearer
  tokens.
- **Native login handoff.** The backend completes the IdP login, then redirects to
  the app with a one-time code.
  - The redirect goes to a private-use URL scheme on mobile and macOS, or a
    loopback URL on Windows and Linux.
  - The app redeems the code with its PKCE verifier.
  - The IdP only ever redirects to the deployment's own HTTPS callback, which is
    why this works with Authelia (which rejects custom schemes).
- **Native apps ask for the server URL** on first launch (HTTPS only).
- **No access-token storage in browsers.** Web apps never see IdP tokens.

### Architecture

- Everything stays in the existing backend (no microservice). The backend can
  also serve the Flutter web build (`WEB_DIR`), so the web app and API share an
  origin. Separate static hosting stays possible.
- New backend feature modules: `auth/`, `users/`, `sessions/` (phase 3),
  `authz/`, `organizations/` and `teams/` (phase 4).

### Authorization

- **Hierarchy:** organization → team → user. A user can be in several teams, and
  a team can be linked to several organizations.
- **Access level (`read` or `write`) is on the team's link to an organization**,
  not on the user's membership. A user's access to an organization is the highest
  level among their teams linked to it (`write` implies `read`).
- **Teams are instance-wide.** No organization owns a team.
  - **Team maintainers** (and platform admins) manage who is in a team.
  - **Organization admins** (and platform admins) decide which teams are linked
    to their organization and at what level. They cannot change a team's members.
- **Team membership role:** `member` or `maintainer`.
- **Platform roles come from the IdP** (the roles claim): admin or user. A token
  with neither is rejected. Platform admins can do everything.
- **Optional IdP group sync per team.** If `teams.idp_group` is set, the team's
  members are the users whose `groups` claim contains that group. It is
  re-evaluated on every request and read-only in the UI.
- On first start there is one **Default** organization, so a single-user homelab
  never has to think about organizations.
- **Kanban boards and other features are out of scope.** Authorization stops at
  the organization. Later features belong to an organization and are checked
  through the `authz` module.
- **Engine: Cedar** (`cedar-policy`), in-process.
  - Built-in `permit` policies are compiled into the binary.
  - Deployers can add **`forbid`-only** policies from `AUTHZ_POLICY_FILE`. A file
    containing any `permit` is refused at startup. (Confirmed by the human.)

  The reasons for forbid-only:
  - custom policies can never widen access by mistake;
  - list queries stay correct when SQL pre-filters candidates and Cedar makes the
    final decision.

  Grants are expressed as data (teams, links, IdP groups), not as custom policies.

### Telemetry

- The telemetry relay (`/telemetry/v1/*`) requires an authenticated user who has
  opted in. Consent is stored per user on the server (`users.telemetry_opt_in`,
  **default false**) and enforced by the relay (`403 telemetry_disabled`).
- Not setting `TELEMETRY_RELAY_UPSTREAM` still turns the relay off for the whole
  instance.
- The relay does not add user identity to forwarded telemetry.
- Errors before login cannot be sent. That is accepted.

### Rate limits and capacity

Defaults are sized for a 10,000-employee company where everyone may reach kanbot
through one corporate IP. That is about 1,000 requests/s at peak (30% active,
roughly 0.3 requests/s each). Every value is configurable. Limits are kept in
memory per server instance, so N instances allow N times the traffic; document
this.

| Limit | Variable(s) | Default |
|---|---|---|
| Per client IP, all requests | `RATE_LIMIT_IP_PER_SECOND`, `RATE_LIMIT_IP_BURST` | 2000/s, burst 4000 |
| Per client IP, failed authentications (401) | `RATE_LIMIT_AUTH_FAILURE_PER_SECOND`, `RATE_LIMIT_AUTH_FAILURE_BURST` | 50/s, burst 500 |
| Per client IP, login endpoints (phase 3) | `RATE_LIMIT_LOGIN_PER_SECOND`, `RATE_LIMIT_LOGIN_BURST` | 100/s, burst 500 |
| Per user | `RATE_LIMIT_USER_PER_SECOND`, `RATE_LIMIT_USER_BURST` | 20/s, burst 100 |
| Per user, telemetry relay | `RATE_LIMIT_TELEMETRY_PER_SECOND`, `RATE_LIMIT_TELEMETRY_BURST` | 1/s, burst 20 |
| Requests in flight per instance | `MAX_IN_FLIGHT_REQUESTS` | 512 (then `503` with `Retry-After`) |
| Database pool per instance | `DATABASE_MAX_CONNECTIONS` | 10 |

- IPv6 clients are keyed by their **/64** prefix, IPv4 by full address.
- Client IPs come from `http/client_ip.rs`, so `TRUSTED_PROXIES` applies.
- Rejections are `429 rate_limited` problems with `Retry-After`, as the existing
  middleware already returns.

### OpenShell (integration is phase 7, later)

- Same issuer for kanbot and OpenShell. Separate audiences: `kanbot-api` and a
  dedicated one such as `openshell-gateway`, never OpenShell's default
  `openshell-cli`. Same roles claim, with separate role names (`kanbot-admin` and
  `kanbot-user`, `openshell-admin` and `openshell-user`).
- Calls from kanbot to OpenShell:
  - use token exchange (RFC 8693) where the IdP supports it;
  - otherwise use a `client_credentials` service account (with `private_key_jwt`
    where supported);
  - never forward one token valid for both services.
- An organization can optionally be linked to one OpenShell workspace. Membership
  syncs one way, kanbot → OpenShell.

### Local development and tests

- **Local IdP: Authelia** (4.39.28 at planning time, pinned by tag and digest) is
  part of the standard local stack, like Postgres, from phase 2 on.
  - Its URL is `https://auth.kanbot.internal:9443`.
  - Developers add `127.0.0.1 auth.kanbot.internal` to `/etc/hosts`.
- **Test signing keys** are committed fixtures under
  `backend/tests/fixtures/oidc/`. They are test-only, with a README that says so
  and shows how they were generated. A future secret scanner needs an allowlist
  for that folder.
- Database and Authelia tests fail rather than skip when their service is missing.

### Frontend

- Web and native (Android, iOS, macOS, Windows, Linux) are all in v1.
- **Full organization and team management in the app for v1.**
- Telemetry toggle in settings, off by default.

## Dependencies

Versions are those current at planning time. Per `AGENTS.md` §2.1, look up the
latest stable release when adding.

| Dependency | Where | Status | Notes |
|---|---|---|---|
| `jsonwebtoken` 12.x | backend | approved | `default-features = false, features = ["rust_crypto"]`. Uses `rsa` 0.10, and `cargo deny` advisories pass. PEM loading for test keys may be enabled only through a dev-dependency feature (`use_pem`) |
| `tokio` `sync` feature | backend | approved | feature of an existing dependency |
| `tower` | backend | approved | features `limit` and `load-shed`. Already in the tree through axum |
| `cedar-policy` 4.x | backend | approved | 4.15.0 at planning time. Passes `cargo deny` with `backend/deny.toml`. Adds about 88 crates. Do not enable `experimental` |
| `getrandom` 0.4.x | backend | approved | already in the tree through sqlx. Use it for all random tokens, never `rand` |
| `sha2` 0.11.x | backend | approved | already in the tree through sqlx. Hashes session tokens and one-time codes |
| `tower-http` `fs` feature | backend | approved | feature of an existing dependency. Serves the web build |
| AEAD crate (`chacha20poly1305` or `aes-gcm`, RustCrypto) | backend | **ask in phase 3** | encrypts stored IdP tokens |
| `flutter_web_auth_2` 6.x | frontend | approved | opens the system browser and receives the redirect on every platform |
| `tonic`, `prost` | backend | **ask in phase 7** | OpenShell gRPC client |
| Authelia image | backend compose, CI | approved | pin by tag and digest |
| Keycloak image 26.8.x | CI | approved for phase 6 | pin by tag and digest |

Rejected:

- `openidconnect`: fails `cargo deny` (RUSTSEC-2023-0071 via `rsa` 0.9) and pulls
  a second `reqwest`.
- The Flutter `oidc` package: no longer needed, and it stores tokens in
  `localStorage` on web.
- `rand`: use `getrandom`.
- OpenFGA: an extra service, no maintained Rust SDK, and dual writes.

## Configuration (all phases)

Existing variables are unchanged: `DATABASE_URL`, `LISTEN_ADDR`,
`CORS_ALLOWED_ORIGINS`, `TRUSTED_PROXIES`, `TELEMETRY_RELAY_UPSTREAM`, `OTEL_*`
and `RUST_LOG`.

| Variable | Phase | Required | Default | Meaning |
|---|---|---|---|---|
| `OIDC_ISSUER` | 2 | yes | | Must equal the tokens' `iss` and the discovery document's `issuer` exactly. HTTPS only |
| `OIDC_AUDIENCE` | 2 | yes | | Accepted access-token audience, for example `kanbot-api` |
| `OIDC_ROLES_CLAIM` | 2 | yes | | Dot path to the roles array (`groups`, `roles`, `realm_access.roles`) |
| `OIDC_ADMIN_ROLE` | 2 | yes | | For example `kanbot-admin`. Must not be empty |
| `OIDC_USER_ROLE` | 2 | yes | | For example `kanbot-user`. Must not be empty |
| `OIDC_SUBJECT_CLAIM` | 2 | no | `sub` | `oid` for Entra ID |
| `OIDC_GROUPS_CLAIM` | 4 | no | value of `OIDC_ROLES_CLAIM` | Dot path to the groups array used for team sync and Cedar `principal.groups` |
| `OIDC_ALLOWED_CLIENTS` | 2 | no | any | Comma-separated client IDs, matched against `azp`, then `client_id`, then `cid` |
| `OIDC_JWKS_TTL` | 2 | no | `3600` | Seconds between JWKS refreshes |
| `OIDC_JWKS_ALLOWED_ORIGINS` | 2 | no | none | Extra HTTPS origins allowed to serve the JWKS |
| `OIDC_CA_FILE` | 2 | no | none | PEM bundle trusted for the IdP, in addition to system roots |
| `OIDC_DANGEROUSLY_ALLOW_INSECURE_HTTP` | 2 | no | `false` | Allows `http://` issuers on numeric loopback hosts only. Development and tests only |
| `DATABASE_MAX_CONNECTIONS` | 2 | no | `10` | Pool size per instance |
| `RATE_LIMIT_*`, `MAX_IN_FLIGHT_REQUESTS` | 2, 3 | no | see the table above | |
| `OIDC_CLIENT_ID` | 3 | yes | | Kanbot's confidential client. Must differ from `OIDC_AUDIENCE` |
| `OIDC_CLIENT_SECRET` / `OIDC_CLIENT_SECRET_FILE` | 3 | yes (one of them) | | Secret (`SecretString`) |
| `OIDC_SCOPES` | 3 | no | `openid profile email offline_access` | Add what the IdP needs for the roles claim, for example `groups` |
| `PUBLIC_URL` | 3 | yes | | External base URL, for example `https://kanbot.example.com`. Used for the callback URL, cookie checks and CSRF origin checks |
| `SESSION_ENCRYPTION_KEYS` / `SESSION_ENCRYPTION_KEYS_FILE` | 3 | yes (one of them) | | Comma-separated base64 keys, each with a key ID. The first encrypts and all decrypt, so keys can be rotated |
| `SESSION_IDLE_TIMEOUT` | 3 | no | `7d` | Session ends after this long without use |
| `SESSION_ABSOLUTE_TIMEOUT` | 3 | no | `30d` | Session ends after this long regardless. Sessions also end when the IdP refuses a refresh |
| `WEB_DIR` | 3 | no | unset (off) | Directory with the Flutter web build to serve at `/` |
| `AUTHZ_POLICY_FILE` | 4 | no | none | Deployer `forbid`-only Cedar policies |

`docs/oidc.md` currently says `SESSION_ENCRYPTION_KEY` (singular). Update it to
the table above in phase 3.

## Security invariants (all phases)

- Never log, trace or put in metrics:
  - tokens, codes, cookies, the client secret or session keys;
  - raw claims other than issuer, subject ID and client ID;
  - display names or emails.

  Record internal IDs (`user.id`) instead.
- Auth failures return stable problem codes only, never the reason.
  - `401` responses carry `WWW-Authenticate: Bearer error="invalid_token"` (RFC
    6750) when a bearer token was presented, and plain `WWW-Authenticate: Bearer`
    when none was.
  - The reason goes only into a bounded metric attribute.
- **Secure by default.** Every route requires authentication except an explicit
  public list:
  - `/health`, `/ready`;
  - from phase 3: `/auth/login`, `/auth/callback`, `/auth/token`, `/auth/config`
    and the web build's static files.

  A test enforces this (phase 2, step 2.6).
- Every outbound call (IdP discovery, JWKS, token endpoint) has connect and total
  timeouts, does not follow redirects, and caps how many response bytes it reads.
- Random values come from `getrandom`, with 32 bytes for every token, code, state
  and nonce. Token comparisons use hashes looked up in the database, never
  string comparison of secrets in memory.
- Fix an existing logging problem as part of phase 2: `AppError` currently logs
  the full `Debug` of `sqlx::Error` (`src/error.rs`, the
  `tracing::error!(error = ?self, ...)` line). Postgres error details can contain
  row values (for example `Key (subject)=(...) already exists`). Log the error
  kind, SQLSTATE and constraint name only, with a test. (Done in 2.5.)

## Phase 1: rules and docs

- [x] **1.1** `backend/AGENTS.md`:
  - add the new modules to the structure (`auth/`, `users/`, later `sessions/`,
    `authz/`, `organizations/`, `teams/`);
  - add the variables above to the config table;
  - add the security invariants above;
  - replace "Still to decide: rate limits" with the rate-limit table;
  - say that Authelia is part of the local stack, with the `/etc/hosts` line and
    the setup script (`backend/dev/auth-setup.sh`), and add both to the "Before
    you finish" commands;
  - describe the test IdP (`tests/common/idp.rs`) and the fixture keys.
- [x] **1.2** `frontend/AGENTS.md`:
  - **Auth callbacks:** replace "No custom URL schemes for auth callbacks". The
    only allowed custom scheme is the kanbot-backend-to-app login handoff,
    received through `flutter_web_auth_2` (`ASWebAuthenticationSession` on Apple,
    Auth Tab or Custom Tabs on Android) and protected by PKCE S256. Desktop uses
    a loopback redirect.
  - **Tokens:** web never stores tokens; it uses the backend's `HttpOnly` session
    cookie and sends the CSRF header. Native stores only the kanbot session token,
    in `TokenStore`.
  - **Telemetry:** export starts only after login and opt-in, and stops on logout.
- [x] **1.3** Commit `docs/oidc.md` and `README.md` (already written), with any
  wording changes needed to match this plan.

## Phase 2: identity

Goal: the API accepts IdP JWT bearer tokens, knows the user, enforces telemetry
consent, applies rate limits and runs against a local Authelia.

### 2.1 Dependencies
- [x] Add `jsonwebtoken` (`rust_crypto`, no default features), tokio `sync`, and
  `tower` (`limit`, `load-shed`). Run `cargo deny check`.

### 2.2 Configuration
- [x] **New file `src/auth/config.rs`:** an `OidcConfig` with validated newtypes
  (`Issuer`, `Audience`, `ClientId`, `RoleName`, `ClaimPath`). `Config` gains an
  `oidc` field and the rate-limit and pool settings. Follow the existing
  `Config::from_lookup` pattern.
- [x] **The backend refuses to start when:**
  - a required variable is missing;
  - the issuer is not HTTPS (unless the insecure flag is set and the host is a
    numeric loopback address);
  - a role name is empty;
  - the audience is in `OIDC_ALLOWED_CLIENTS` (and, from phase 3, equals
    `OIDC_CLIENT_ID`);
  - a claim path has an empty segment;
  - the CA file is unreadable or invalid;
  - a rate limit is zero or not a number.
- [x] **Tests:** unit tests for every rule, plus `proptest` for `ClaimPath`
  parsing.

### 2.3 Discovery and keys (`src/auth/discovery.rs`, `src/auth/keys.rs`)
- [x] **HTTP client:** a dedicated `reqwest` client with a 2 s connect timeout, a
  5 s total timeout, no redirects, and the extra CA from `OIDC_CA_FILE`. Bodies
  are read in chunks and capped at 64 KiB for discovery and 256 KiB for the JWKS.
- [x] **Discovery** (`<issuer>/.well-known/openid-configuration`): its `issuer`
  must equal `OIDC_ISSUER` byte for byte. `jwks_uri` must be HTTPS (or allowed
  loopback HTTP) on the issuer's origin or in `OIDC_JWKS_ALLOWED_ORIGINS`. Keep
  `token_endpoint`, `authorization_endpoint` and `end_session_endpoint` (if
  present) for phase 3.
- [x] **JWKS:**
  - keep only keys with `use` = `sig` or absent;
  - accepted key types: RSA with a modulus of at least 2048 bits, EC P-256 and
    P-384, and OKP Ed25519;
  - skip any other key, never fail on it.

  Each key's algorithm is its `alg` if present (it must be on the allowed list:
  RS256/384/512, PS256/384/512, ES256, ES384, EdDSA). Otherwise derive it: RSA →
  RS256, P-256 → ES256, P-384 → ES384, Ed25519 → EdDSA.
- [x] **Key cache:**
  - Readers never hold a lock across `.await`.
  - A background task refreshes every `OIDC_JWKS_TTL`.
  - An unknown `kid` triggers a single refresh shared by all waiting requests, at
    most once per second.
  - A failed refresh, or one that yields no usable keys, keeps the last good set.
- [x] **Startup:** the server starts even if the IdP is unreachable, retrying with
  backoff. Until keys are loaded:
  - `/ready` returns `503`;
  - authenticated requests get `503 unavailable` (not `401`). (Lands with the
    middleware in 2.6: `KeyLookup::NotLoaded`.)

### 2.4 Token validation (`src/auth/token.rs`)
- [x] A pure function: token, key set, config and the current time go in; a
  `Principal` or a `Rejection` reason comes out. In order:
  1. Reject tokens over 16 KiB, or anything that is not three base64url segments
     (this also rejects opaque tokens).
  2. The header must have `kid` and `alg`. Reject `crit` (verified:
     `jsonwebtoken` 12 rejects every `crit` except `["b64"]` with `b64` set, so
     kanbot rejects any `crit` itself). `alg` must equal the key's derived
     algorithm. `none` and `HS*` are never accepted.
  3. Verify the signature and the standard claims with `jsonwebtoken`:
     - required: `exp`, `iss`, `aud`, `sub`;
     - `iss` exact;
     - `aud` contains `OIDC_AUDIENCE` (string or array);
     - `nbf` checked when present;
     - 60 s leeway.

     Then check `iat` yourself: if present, it must not be in the future (beyond
     the leeway).
  4. Read the subject (`OIDC_SUBJECT_CLAIM`) and the roles array (dot path; it
     must be an array; non-string items are ignored). Admin implies user. Neither
     role → `403`.
  5. If `OIDC_ALLOWED_CLIENTS` is set, the client ID (`azp`, then `client_id`,
     then `cid`) must be listed.
  6. The `Principal` holds issuer, subject, platform role, client ID, display
     name (`name`, then `preferred_username`), and groups (for phase 4).

### 2.5 Users
- [x] **Migration:**

  ```sql
  CREATE TABLE users (
    id               uuid PRIMARY KEY,
    issuer           text NOT NULL,
    subject          text NOT NULL,
    display_name     text,
    platform_role    text NOT NULL CHECK (platform_role IN ('admin', 'user')),
    telemetry_opt_in boolean NOT NULL DEFAULT false,
    created_at       timestamptz NOT NULL DEFAULT now(),
    last_seen_at     timestamptz NOT NULL DEFAULT now(),
    disabled_at      timestamptz,
    UNIQUE (issuer, subject)
  );
  ```

- [x] **`users/repo.rs`:** one query per authenticated request. It inserts, or
  updates only when `last_seen_at` is more than 5 minutes old or the display name
  or role changed. It always returns `(id, disabled_at, telemetry_opt_in)`.
  - Pattern: a CTE with `INSERT ... ON CONFLICT ... DO UPDATE ... WHERE ...
    RETURNING`, combined with a `SELECT` for the row that was not updated.
- [x] **Disabled user** → `403` with the new error code `account_disabled`.
- [x] **Endpoints** (done in 2.6: they need the authentication middleware):
  - `GET /me`: `{ id, display_name, platform_role, telemetry_opt_in }`.
  - `PUT /me/preferences`: `{ telemetry_opt_in: bool }`, with
    `deny_unknown_fields`.

### 2.6 Authentication middleware, extractors and contract
- [x] **Authentication middleware**, applied to the API router:
  - If credentials are present, validate them, upsert the user, and insert the
    authenticated user into request extensions.
  - Invalid credentials → `401` immediately (never treated as anonymous), counted
    by the failed-authentication limiter.
  - No credentials → continue without a user.

  In phase 3 the same middleware also accepts kanbot sessions.
- [x] **Extractors in `src/http/extract.rs`:**
  - `AuthUser`: requires the extension, else `401`.
  - `RequireAdmin`: platform admin only, else `403`.
- [x] **OpenAPI:**
  - add a `bearer` security scheme (HTTP bearer, JWT);
  - protected operations declare it and document their `401` and `403`
    responses;
  - add `account_disabled` and `telemetry_disabled` to `ErrorCode`, with tests.
- [x] **Secure-by-default test:**
  - It walks every operation in `http::openapi()`.
  - Each must either be on the public list, or declare security and return `401`
    without credentials.
  - The telemetry relay routes (not in OpenAPI) are covered explicitly (in 2.7,
    when the relay starts requiring a user).

### 2.7 Telemetry relay
- [x] **Access:** require an authenticated user with `telemetry_opt_in = true`,
  else `403 telemetry_disabled`.
- [x] **Limits:** per-user limiter (`RATE_LIMIT_TELEMETRY_*`) replacing the current
  per-IP-only one; keep the existing body, type and encoding protections. (An
  in-memory GCRA limiter in `rate_limit.rs`: `tower_governor` cannot skip
  anonymous requests, and does not re-export `governor`.)
- [x] **Docs:** update `backend/AGENTS.md` ("The telemetry relay is public" is no
  longer true).

### 2.8 Rate limits and load shedding
- [x] **IPv6 keying:** change the IP key extractor in
  `http/middleware/rate_limit.rs` to key IPv6 by /64.
- [x] **Layers on the API router:**
  - per-IP limiter;
  - failed-authentication limiter (checked before validating credentials);
  - per-user limiter (keyed by the user ID from request extensions, after
    authentication);
  - global in-flight cap: `tower` `ConcurrencyLimit` + `LoadShed`, turned into
    `503` with `Retry-After` by `ensure_problem_body`. (`GlobalConcurrencyLimit`:
    `Router::layer` wraps each route separately.)
- [x] **Pool size:** `db::pool` uses `DATABASE_MAX_CONNECTIONS`.
- [x] **Readiness:** `/ready` requires migrations applied **and** keys loaded.
- [x] **Metric:** `kanbot.auth.token.rejections` (counter), with a `reason`
  attribute from a fixed list:
  - `malformed`, `too_large`, `unknown_key`, `bad_signature`, `bad_algorithm`;
  - `expired`, `not_yet_valid`, `wrong_issuer`, `wrong_audience`;
  - `missing_claim`, `no_role`, `client_not_allowed`, `disabled`.

  Add a test with the in-memory exporter.

### 2.9 Local Authelia
- [x] **`backend/dev/auth-setup.sh`** (POSIX shell plus `openssl`) generates into
  a git-ignored `backend/dev/.generated/`:
  - a local CA, and a certificate for `auth.kanbot.internal`;
  - Authelia's JWT, session and storage secrets and its OIDC HMAC secret;
  - an RSA signing key for the OIDC provider.

  It is idempotent.
- [x] **`backend/dev/authelia/configuration.yml`** (committed, no secrets; secrets
  come in through Authelia's `*_FILE` environment variables):
  - TLS on port 9443 with the generated certificate;
  - `session.cookies` for domain `kanbot.internal` with `authelia_url`
    `https://auth.kanbot.internal:9443` (verified: Authelia 4.39.28 accepts
    `kanbot.internal`);
  - SQLite storage, filesystem notifier;
  - file authentication backend;
  - access-control policy `one_factor` for the clients;
  - OIDC lifespans: access token 5 minutes, refresh token 30 days.
- [x] **OIDC client in that config:**
  - `client_id: kanbot`, confidential, with a **documented dev-only secret**
    whose PBKDF2 hash is committed;
  - `access_token_signed_response_alg: RS256`, `audience: ['kanbot-api']`;
  - claims policy copying `groups`, `preferred_username` and `name` into the
    access token;
  - PKCE S256 required;
  - scopes `openid profile email groups offline_access`;
  - grants `authorization_code` and `refresh_token`;
  - redirect URI `https://localhost:3000/auth/callback` (adjust when phase 3 fixes
    the dev URL);
  - `consent_mode: pre-configured`.
- [x] **`backend/dev/authelia/users_database.yml`** (committed, Argon2 hashes of
  documented dev-only passwords):
  - `alice` in `kanbot-admin`;
  - `bob` in `kanbot-user`;
  - `carol` with no kanbot group;
  - `dave` in `kanbot-user` and `contractors` (for phase 4 tests).
- [x] **`backend/compose.yaml`:** an `authelia` service (pinned tag and digest),
  started by default with Postgres, port `9443`, network alias
  `auth.kanbot.internal`.
- [x] **`backend/dev/dev.env`** (committed, dev-only values, no real secrets): the
  `OIDC_*` variables for the local stack (`OIDC_ISSUER=https://auth.kanbot.internal:9443`,
  `OIDC_AUDIENCE=kanbot-api`, `OIDC_ROLES_CLAIM=groups`, the roles,
  `OIDC_CA_FILE=dev/.generated/ca.crt`).
- [x] **Programmatic login helper**, shared between `examples/dev_token.rs` and the
  tests (for example through a `#[path]` module, not copied):
  1. Log in through Authelia's first-factor API with a manual cookie jar (no new
     crates; verified for 4.39.28: `POST /api/firstfactor`
     `{username, password, keepMeLoggedIn}`, then for the first authorization
     `POST /api/oidc/consent` `{flow_id, client_id, consent, pre_configure}`).
     PKCE uses `sha2` (approved) as a dev-dependency.
  2. Run the authorization code flow with PKCE, reading the `Location` header
     instead of following the redirect.
  3. Exchange the code and return the access token.

  `cargo run --example dev-token -- alice` prints a token for `curl`.
- [x] **`tests/authelia.rs`:**
  - real tokens for `alice` → `/me` 200 admin;
  - `bob` → 200 user;
  - `carol` → 403;
  - a token for a different audience → 401.
- [x] **CI (`backend.yml` test job):** add the hosts entry, run the setup script,
  start compose (Postgres and Authelia), then run the tests. Keep pinned digests.
  Update the "Before you finish" commands in `backend/AGENTS.md`.

### 2.10 Test IdP and tests
- [x] **Fixtures** (`backend/tests/fixtures/oidc/`, with a README saying test-only
  and the `openssl` commands used):
  - RSA-2048 keys A and B (rotation);
  - an RSA-1024 key (too weak);
  - P-256, P-384 and Ed25519 keys;
  - their public JWKs.
- [x] **`tests/common/idp.rs`:** an axum server on `127.0.0.1:0` serving discovery
  and a JWKS that can be changed at runtime (rotate, empty, broken, oversized,
  redirect, slow), counting requests, plus a helper that signs tokens with any
  claims and header. The app under test uses it through
  `OIDC_DANGEROUSLY_ALLOW_INSECURE_HTTP`.
- [x] **Required test cases**, each failing without the code it tests:
  - **Accepted:** each supported algorithm.
  - **Time:** expired; `nbf` in the future; `iat` in the future.
  - **Claims:** each required claim missing; `iss` differing by a trailing slash;
    `aud` as string, as array, and without ours.
  - **Algorithms and keys:**
    - `alg: none`;
    - HS256 signed with the RSA public key bytes;
    - header `alg` not matching the key;
    - missing `kid`;
    - unknown `kid`, then a refresh finds it;
    - unknown `kid` still unknown after refresh;
    - refresh throttled to once per second;
    - RSA-1024 key ignored;
    - `use: enc` key ignored.
  - **Malformed input:** `crit` header; oversized token; opaque token; invalid
    base64.
  - **Roles:** claim missing; not an array; nested path (`realm_access.roles`);
    admin counts as user; neither role → 403.
  - **Client allowlist:** via `azp`, `client_id` and `cid`.
  - **ID-token confusion:** an ID token (`aud` = client ID) is rejected.
  - **Discovery:**
    - issuer mismatch;
    - `jwks_uri` on another origin, with and without the allowlist;
    - redirect not followed;
    - oversized body;
    - timeout;
    - empty JWKS keeps the previous keys;
    - not ready until keys load, then ready.
  - **HTTP:**
    - `/me`: 401 with `WWW-Authenticate`, 200, user created once, display name
      updated, disabled → 403 `account_disabled`, 503 before keys load;
    - `PUT /me/preferences`;
    - relay: 401 without credentials, 403 without opt-in, accepted with opt-in;
    - every rate limiter, including IPv6 /64 grouping;
    - load shedding;
    - the secure-by-default test.
  - **Telemetry:** no token or claim values appear in spans, logs or metrics.
- [ ] Add a `cargo-fuzz` target for token parsing and validation (`fuzz/`, run
  manually). (Waiting for approval of `libfuzzer-sys`, which cargo-fuzz needs
  and the dependency table does not list.)

### 2.11 Contract and docs
- [x] Regenerate `backend/openapi.json` and the frontend client
  (`frontend/AGENTS.md` §3). Run the frontend checks. (swagger_parser writes
  untyped `[]` scopes for security requirements, which strict inference
  refuses; `tool/generated_code_fixes.dart` types them, with tests.)
- [x] Update `docs/oidc.md` (bearer validation is now implemented) and
  `backend/AGENTS.md`.

**Phase 2 done when** every check in `backend/AGENTS.md` passes (including
coverage ≥ 80% and `cargo mutants` on changed code), the frontend checks pass
after regenerating the client, and the Authelia tests pass locally and in CI.

## Phase 3: login through the kanbot backend (sessions)

- [ ] **3.1 Dependencies:** ask the human to approve an AEAD crate
  (`chacha20poly1305` or `aes-gcm`, RustCrypto; check `cargo deny`). Add
  `getrandom`, `sha2` and the tower-http `fs` feature.
- [ ] **3.2 Configuration:** the phase 3 variables in the configuration table,
  validated as in 2.2.
- [ ] **3.3 Migrations:**
  - `login_attempts`: `id`, `state_hash`, `nonce`, `pkce_verifier` (encrypted),
    `platform` (`web`/`native`), `app_redirect_uri`, `app_code_challenge`,
    `created_at`, `expires_at` (10 minutes), `used_at`.
  - `sessions`: `id`, `token_hash` (unique), `user_id` → `users`, `kind`
    (`web`/`native`), `idp_access_token`, `idp_refresh_token`, `idp_id_token`
    (encrypted, with key ID), `access_expires_at`, `created_at`, `last_used_at`,
    `idle_expires_at`, `absolute_expires_at`.
  - `login_codes`: one-time codes for native: `code_hash`, `session_id`,
    `app_code_challenge`, `expires_at` (60 s), `used_at`.
- [ ] **3.4 Formats:**
  - session tokens: `kbs_` plus 32 random bytes in base64url;
  - one-time codes: `kbc_` plus 32 bytes;
  - only SHA-256 hashes are stored;
  - IdP tokens are encrypted with the AEAD, with the session ID as associated
    data and a key-ID prefix for rotation.
- [ ] **3.5 `GET /auth/login`**, query `platform=web|native`:
  - **native** adds `redirect_uri`, `code_challenge` and
    `code_challenge_method=S256`;
  - **allowed native redirects:** `<app-scheme>:/auth/done`, where `<app-scheme>`
    is the app's final reverse-DNS ID (see the open items), and
    `http://127.0.0.1:{any port}/auth/done` (verify whether `flutter_web_auth_2`
    on Windows and Linux uses `127.0.0.1` or `localhost`, and allow exactly what
    it uses);
  - creates a login attempt with state, nonce and IdP PKCE;
  - **web** also sets a `__Host-kanbot_login` cookie (`HttpOnly`, `Secure`,
    `SameSite=Lax`, short-lived) that binds the attempt to the browser, which
    prevents login CSRF;
  - redirects to the IdP's authorization endpoint.
- [ ] **3.6 `GET /auth/callback`:**
  1. Check `state` (and the login cookie for web), and that the attempt is unused
     and unexpired.
  2. Exchange the code at the token endpoint (`client_secret_basic`, PKCE
     verifier, timeouts, no redirects).
  3. Validate the ID token (signature from the phase 2 key cache; `iss`;
     `aud` = client ID; `azp` = client ID if present; `nonce`; `exp`/`iat`).
  4. Validate the access token with the phase 2 rules. No role → error.
  5. Upsert the user and create the session.
  6. **Web:** set `__Host-kanbot_session` (`HttpOnly`, `Secure`,
     `SameSite=Strict`, `Path=/`) and redirect to `/`. **Native:** create a
     one-time code and redirect to `app_redirect_uri?code=...`.
  7. On failure, redirect with a stable `error` parameter (`access_denied`,
     `login_failed`, `no_role`): web to `/login`, native to `app_redirect_uri`.
     Never include details.
- [ ] **3.7 `POST /auth/token`:**
  - request `{ code, code_verifier }`; checks S256 against the stored challenge,
    single use;
  - returns `{ session_token, expires_at }`.
- [ ] **3.8 `POST /auth/logout`:**
  - deletes the session;
  - returns the IdP `end_session_endpoint` URL with `id_token_hint` and
    `post_logout_redirect_uri` when discovery advertises one (Authelia does not).
- [ ] **3.9 `GET /auth/config`** (public): the login URL, whether telemetry is
  available on this instance, and the server version.
- [ ] **3.10 Sessions in the authentication middleware:**
  - accept `__Host-kanbot_session` or `Authorization: Bearer kbs_...`;
  - look up the hash, check expiry, update `last_used_at` at most once a minute;
  - refresh the IdP access token when it expires within 60 s, under a row lock
    (`SELECT ... FOR UPDATE`), so concurrent requests or instances never use the
    same refresh token twice;
  - store the rotated refresh token;
  - re-check the new access token with the phase 2 rules (roles are re-evaluated
    on every refresh);
  - the IdP refusing the refresh (`invalid_grant`) → delete the session → 401.
- [ ] **3.11 CSRF for cookie sessions:** state-changing methods require `Origin`
  equal to `PUBLIC_URL`'s origin **and** the header `X-Kanbot-CSRF: 1`. Bearer
  requests are exempt.
- [ ] **3.12 Cleanup:** a periodic task deletes expired login attempts, codes and
  sessions in bounded batches.
- [ ] **3.13 Disabled users:** disabling a user deletes their sessions.
- [ ] **3.14 Web serving** (`WEB_DIR`):
  - static files with an SPA fallback to `index.html`;
  - `index.html` gets `Cache-Control: no-store`, hashed assets are cacheable;
  - HTML responses get the web Content-Security-Policy as an HTTP header, taken
    from `frontend/tool/web_csp.dart` and moved to the backend, which becomes its
    single source; API responses keep `default-src 'none'`;
  - with same-origin serving, `CORS_ALLOWED_ORIGINS` becomes optional.
- [ ] **3.15 Rate limits:** login endpoints get the per-IP login limiter.
- [ ] **3.16 OpenAPI:** add a `session` security scheme (cookie) next to `bearer`.
  Extend the public list and the secure-by-default test.
- [ ] **3.17 Tests:**
  - the full web flow against Authelia end to end;
  - the native handoff (code redeemed with the right verifier; wrong verifier,
    reuse, expiry and disallowed redirect all rejected);
  - wrong or replayed `state`; missing login cookie;
  - ID token with wrong `nonce`, `aud` or `azp`;
  - refresh, including rotation, the concurrent-refresh lock, and `invalid_grant`
    ending the session;
  - CSRF accepted and rejected;
  - idle and absolute timeouts;
  - logout;
  - encryption-key rotation (old key decrypts, new key encrypts);
  - cleanup;
  - static serving and headers.
- [ ] **3.18 Docs:** update `docs/oidc.md` (the login flow is implemented; config
  names), both `AGENTS.md` files, and the contract.

## Phase 4: authorization (Cedar)

- [ ] **4.1 Dependency:** add `cedar-policy` (no `experimental`). Run `cargo deny`.
- [ ] **4.2 Migrations:**
  - `organizations`: `id`, `slug` (unique), `name`, `openshell_workspace` (null
    until phase 7), timestamps.
  - `organization_admins`: `organization_id`, `user_id`, primary key on both.
  - `teams`: `id`, `slug` (unique), `name`, `idp_group` (unique, nullable),
    timestamps.
  - `team_members`: `team_id`, `user_id`, `role` (`member`/`maintainer`),
    `source` (`manual`/`idp`), primary key on `(team_id, user_id)`.
  - `organization_teams`: `organization_id`, `team_id`, `access`
    (`read`/`write`), primary key on both.
  - `audit_log`: `id`, `at`, `actor_user_id`, `action`, `target_type`,
    `target_id`, `policy_ids` (`text[]`), `details` (`jsonb`, IDs only).
  - Insert the **Default** organization (slug `default`) in a migration.
- [ ] **4.3 Cedar model** (`src/authz/schema.cedarschema`,
  `src/authz/policies.cedar`, embedded with `include_str!` and validated at
  startup and in tests):
  - **Entities:**
    - `User`: attributes `platformRole`, `groups` (`Set<String>`, from
      `OIDC_GROUPS_CLAIM`), `clientId`. Parents are its teams.
    - `Team`: parents are organization access groups.
    - `OrgGroup`: two per organization, `<org-id>/read` and `<org-id>/write`,
      where `write` is a member of `read`.
    - `Organization`: attributes `readers`, `writers` and `admins` (entity
      references).
  - **Context:** `via` (`web`, `native` or `bearer`) and `ip` (the `ipaddr`
    extension).
  - **Actions:** `read`, `write` (for organization data, used by future features),
    and `manageOrganization`, `manageOrganizationAdmins`, `manageTeamLinks`,
    `createTeam`, `manageTeam`, `manageTeamMembers`, `setTeamIdpGroup`,
    `createOrganization`, `deleteOrganization`.
  - **Built-in permits:**
    - platform admins: all actions;
    - organization admins: `read`, `write`, `manageOrganization`,
      `manageOrganizationAdmins` and `manageTeamLinks` on their organization;
    - members of the read group: `read`; of the write group: `write`;
    - team maintainers: `manageTeamMembers` and `manageTeam` on their team;
    - organization admins and platform admins: `createTeam` (the creator becomes
      maintainer);
    - platform admins only: `createOrganization`, `deleteOrganization` and
      `setTeamIdpGroup`.
- [ ] **4.4 `src/authz/`:**
  - `can(principal, action, resource) -> Result<Decision, AppError>`:
    - loads only the entities that decision needs with SQL (the user's teams, the
      relevant organization's links and admins);
    - evaluates with Cedar;
    - returns `403` on deny;
    - records the deciding policy IDs for the audit log.
  - `visible(principal, type) -> Vec<Id>`:
    - SQL returns the candidates the built-in permits could allow (a superset);
    - Cedar checks each;
    - this is correct only because deployer policies are forbid-only.
  - Write a test, and a short code comment at `visible()`, explaining that this
    pre-filter relies on deployer policies being forbid-only. Anyone allowing
    deployer `permit` policies later must replace the pre-filter.
  - Deployer policies come from `AUTHZ_POLICY_FILE`. The server refuses to start
    if the file fails to parse or validate against the schema, or contains a
    `permit`.
- [ ] **4.5 IdP group sync:**
  - On each authenticated request, compare the principal's groups with
    `teams.idp_group`.
  - Insert or delete `source = 'idp'` memberships so they match. Write only when
    something changed.
  - IdP-sourced memberships cannot be edited through the API (`409 conflict`).
- [ ] **4.6 API** (all through `authz::can`, all documented in OpenAPI, all
  writing the audit log):
  - **Organizations:**
    - `GET /organizations` (visible ones), `POST /organizations`;
    - `GET`, `PATCH` and `DELETE /organizations/{id}` (delete removes links and
      admins; the Default organization cannot be deleted);
    - `GET /organizations/{id}/admins`, and `PUT` or `DELETE
      /organizations/{id}/admins/{user_id}`;
    - `GET /organizations/{id}/teams`, `PUT /organizations/{id}/teams/{team_id}`
      (`{ access }`), `DELETE /organizations/{id}/teams/{team_id}`.
  - **Teams:**
    - `GET /teams`, `POST /teams`;
    - `GET`, `PATCH` and `DELETE /teams/{id}` (`PATCH` of `idp_group` is platform
      admin only);
    - `GET /teams/{id}/members`, `PUT /teams/{id}/members/{user_id}`
      (`{ role }`), `DELETE /teams/{id}/members/{user_id}`.
  - **Users:** `GET /users?query=` (users who have signed in at least once;
    restricted to platform admins, organization admins and team maintainers).
  - **Audit:** `GET /audit` (platform admins).
- [ ] **4.7 Tests:**
  - every built-in policy, allowed and denied;
  - the schema validation test;
  - a property test that SQL candidates ⊇ the Cedar-allowed set for random
    memberships and links;
  - a deployer `forbid` takes effect (for example "`contractors` cannot `write`");
  - startup refuses a policy file containing a `permit`;
  - IdP group sync add and remove;
  - an IdP-sourced membership edit gets 409;
  - Default organization exists and cannot be deleted;
  - audit entries are written;
  - mutation testing.
- [ ] **4.8 Docs:** an authorization section in `backend/AGENTS.md` (every feature
  must call `authz`), a deployer policy guide with examples (new
  `docs/authorization.md`), and the contract.

## Phase 5: frontend

- [ ] **5.1** Set the real application ID (it is still `com.example.kanbot` on
  every platform; ask the human for it) and derive `<app-scheme>` from it. Add
  `flutter_web_auth_2` and its per-platform setup.
- [ ] **5.2 Native server selection:**
  - a server URL screen (HTTPS only), stored locally, fetching `/auth/config`;
  - `ApiClient` takes its base URL from this at runtime;
  - `API_BASE_URL` remains only as an optional build-time default.
- [ ] **5.3 Web:**
  - API base URL is relative (same origin);
  - requests send the session cookie (same-origin credentials) and
    `X-Kanbot-CSRF: 1` on state-changing methods;
  - `tool/build_web.dart` no longer injects the CSP meta tag (the backend sends
    the header);
  - update `web_csp.dart` and `build_web.dart` and their tests accordingly.
- [ ] **5.4 Login:**
  - **native:** create a PKCE pair, open `/auth/login?platform=native&...` with
    `flutter_web_auth_2`, receive the code, redeem it at `/auth/token`, store the
    session token in `TokenStore`;
  - **web:** navigate to `/auth/login?platform=web`;
  - map the `error` parameter to localized messages.
- [ ] **5.5 Auth state:**
  - an auth repository and view model, with `GET /me` on start;
  - `go_router` redirects for protected routes, with one test per protected route
    proving a logged-out user cannot reach it;
  - `401` → back to login;
  - logout calls `/auth/logout`, clears `TokenStore`, and opens the IdP logout URL
    if one is returned.
- [ ] **5.6 Telemetry:**
  - `lib/config/telemetry.dart` no longer starts at app launch; export starts
    after login when `/me` says `telemetry_opt_in`, and stops on logout or
    opt-out;
  - settings has a toggle bound to `PUT /me/preferences` (off by default);
  - exports carry the session (cookie on web, bearer on native) and the CSRF
    header on web.
- [ ] **5.7 Organization and team management (full, for v1):**
  - **Organizations:** list, create (platform admin), rename, delete;
  - **Organization detail:** admins (add or remove through user search), linked
    teams with a `read`/`write` selector, add or remove links;
  - **Teams:** list, create, rename, delete;
  - **Team detail:** members and maintainers (add through user search, change
    role, remove), the IdP group field (platform admins only), IdP-synced members
    shown read-only;
  - an audit log view for platform admins;
  - controls the user may not use are hidden; the backend still enforces
    everything.
- [ ] **5.8 Tests:**
  - unit tests for the repositories and view models (strict mocks);
  - widget tests for login, server URL, settings and every management screen;
  - an integration test on Linux desktop logging in against the local Authelia
    through the loopback handoff.

  Run all checks in `frontend/AGENTS.md`.

## Phase 6: wider IdP coverage and hardening

- [ ] **6.1 Keycloak in CI:** add Keycloak 26.8.x (pinned) as a second IdP in the
  end-to-end matrix, with a realm export committed. Resolve every **(verify)**
  item for Keycloak in `docs/oidc.md`.
- [ ] **6.2 authentik:** test whether a scope mapping can set `aud` without
  breaking ID tokens. Mark it supported (with setup steps) or unsupported in
  `docs/oidc.md`.
- [ ] **6.3 Fuzzing:** fuzz targets for the login callback parameters and Cedar
  entity building. Run all fuzz targets and fix what they find.
- [ ] **6.4 Security review:** run `/security-review` on the auth and authz code.
  Add workflow linting (`zizmor` or `actionlint`) and secret scanning (gitleaks,
  with an allowlist for `backend/tests/fixtures/oidc/` and `backend/dev/`) to CI,
  pinned per `AGENTS.md` §2.1.
- [ ] **6.5 Operator docs:**
  - Kubernetes notes (one issuer URL, private CA, rate limits multiply with
    instances, `TRUSTED_PROXIES`);
  - migration warnings (changing `OIDC_ISSUER` or `OIDC_SUBJECT_CLAIM` detaches
    existing users);
  - native app TLS (use publicly trusted certificates).

## Phase 7: OpenShell integration (later)

- [ ] **7.1** Check OpenShell's `.proto` files for workspace membership APIs and
  roles, and whether the gateway accepts an `aud` array containing its audience.
  Report to the human before building.
- [ ] **7.2** Ask the human to approve `tonic` and `prost`. Generate the client from
  the `.proto` files of the deployed OpenShell version. Document the supported
  version pairs.
- [ ] **7.3** Use token exchange (RFC 8693) for user-initiated calls where the IdP
  supports it (Keycloak, Okta, authentik 2026.8+). Otherwise use a
  `client_credentials` service account. Never forward a token valid for both
  services.
- [ ] **7.4** Link organizations to OpenShell workspaces (`openshell_workspace`) and
  sync membership one way, kanbot → OpenShell.

## Open items

- **Application ID** (needed for phase 5, and for the native redirect allowlist
  in phase 3): currently `com.example.kanbot`. Ask the human.
- Items to verify:
  - ~~Authelia accepts `kanbot.internal` as a cookie domain~~ (yes, 2.9);
  - ~~the shape of Authelia's first-factor API in 4.39~~ (resolved in 2.9);
  - ~~whether `jsonwebtoken` rejects `crit`~~ (resolved in 2.4: not fully, so
    kanbot does);
  - which loopback host `flutter_web_auth_2` uses on desktop;
  - the **(verify)** items in `docs/oidc.md`.

## Out of scope

- Kanban boards and any other product feature.
- Passwords and local accounts, social logins, MFA inside kanbot (it is the IdP's
  job), and SCIM provisioning.
- Multi-tenant Entra ID (`common` issuer).
- Per-board grants and nested teams. Revisit with Cedar when features exist.
- Other items from the earlier repository review:
  - the backend trusting inbound `traceparent` from any client;
  - a Dockerfile and deployment;
  - release signing;
  - the frontend coverage gate.

  Track them separately.

## Progress

Tick as steps land (each step is one commit on `auth/oidc`).

- Phase 1: [x] 1.1 [x] 1.2 [x] 1.3
- Phase 2: [x] 2.1 [x] 2.2 [x] 2.3 [x] 2.4 [x] 2.5 [x] 2.6 [x] 2.7 [x] 2.8 [x] 2.9 [ ] 2.10 (fuzz target pending) [x] 2.11
- Phase 3: [ ] 3.1 … [ ] 3.18
- Phase 4: [ ] 4.1 … [ ] 4.8
- Phase 5: [ ] 5.1 … [ ] 5.8
- Phase 6: [ ] 6.1 … [ ] 6.5
- Phase 7: [ ] 7.1 … [ ] 7.4
