# OIDC authentication

> **Status: implemented.** This document describes how kanbot
> authenticates users with an external OpenID Connect (OIDC) identity provider
> (IdP), and how to set up each supported IdP: bearer-token validation (the
> API as a resource server), and the login flow through the kanbot backend
> with sessions for the web and native apps. It is tested end to end against
> Authelia and Keycloak (the backend), and the Linux desktop app's sign-in
> against Authelia. Authorization (organizations, teams, Cedar) is in
> [`authorization.md`](authorization.md). Configuration names may still
> change before the first release. The provider setups other than Authelia
> and Keycloak have not been tested with kanbot yet. Facts about each IdP
> were checked against its official documentation on 2026-11-20, at the
> version noted in its section. The implementation plan is
> [`docs/plan/auth.md`](plan/auth.md).

## How kanbot uses OIDC

Kanbot has no user accounts or passwords of its own. All users sign in at an
external IdP, which manages users, groups, multi-factor authentication and login
policy. Kanbot is self-hosted, so each deployment uses its own IdP and its own
domain.

**Kanbot's own apps (web and native) sign in through the kanbot backend.** The
backend is the only OIDC client registered at the IdP, as a confidential client:

```
App ──opens the system browser──▶ https://<kanbot-host>/auth/login
                                       │ authorization code flow with PKCE
                                       ▼
                                  IdP sign-in page
                                       │ redirect to https://<kanbot-host>/auth/callback
                                       ▼
                                  kanbot backend: exchanges the code, validates the
                                  tokens, stores them server-side, creates a session
                                       │
     web:    sets an HttpOnly session cookie and redirects to the app
     native: redirects to dev.sideral.kanbot:/auth/done?code=<one-time code>
             (Windows and Linux: http://127.0.0.1:<port>/auth/done)
                                       ▼
App exchanges the one-time code and its PKCE verifier for a kanbot session token
```

- **The IdP only ever redirects to the deployment's own HTTPS URL.** This works
  with every supported IdP, including those that reject custom URL schemes
  (Authelia).
- **IdP access and refresh tokens never reach the apps.** The backend keeps
  them encrypted and refreshes them. Signing out or disabling a user in kanbot
  ends their sessions immediately. Signing out also revokes the refresh token
  at the IdP (RFC 7009) when discovery lists a `revocation_endpoint`, so an
  offline session there ends too. Only the web app is sent to the IdP's
  logout page, with the ID token as `id_token_hint` (it is no access token:
  its audience is `OIDC_CLIENT_ID`, never `OIDC_AUDIENCE`); native apps sign
  out without opening a browser.
- **Refreshing** holds no database connection or lock while the IdP answers:
  one request takes a short lease and refreshes, the others keep using the
  stored token while it is valid. The refresh finishes and is stored even if
  the request that started it goes away. Only `invalid_grant` ends a session;
  any other refusal (a wrong client secret, an outage) is the server's
  problem, and the session lasts until its token expires. A session the IdP
  issued no refresh token for ends when its access token expires. While the
  IdP rotates its signing keys, a stored token signed with a key kanbot has
  not fetched yet gets `503`, not a sign-out.
- **The native handoff is protected.** The one-time code is bound to the app's
  PKCE challenge, expires within about a minute and can be used once, as
  recommended by [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252). An app
  that intercepts the redirect cannot redeem the code.
- **`dev.sideral.kanbot`** is the app's reverse-DNS application ID. The app receives the redirect through the system browser
  (`ASWebAuthenticationSession` on Apple platforms, Auth Tab or Custom Tabs on
  Android). Windows and Linux use a loopback redirect instead,
  `http://127.0.0.1:<port>/auth/done`. No App Links or Universal Links are involved,
  because the kanbot project controls no deployment's domain.

**Other clients (CLI, scripts, CI, agents, other services) call the API with an
IdP-issued JWT access token** in `Authorization: Bearer <token>`. Kanbot validates
it locally against the IdP's published signing keys (JWKS). In this role the API
is an OAuth 2.0 resource server.

Session-based and bearer-token requests go through the same validation. For a
session, the backend checks the stored access token with exactly the same rules,
so authorization never depends on how the caller signed in.

[NVIDIA OpenShell](https://docs.nvidia.com/openshell/how-it-works/gateways/authentication)
validates bearer tokens the same way. One IdP can serve both kanbot and OpenShell.
See [OpenShell alignment](#openshell-alignment).

## Requirements for the IdP

An IdP works with kanbot only if it can do all of the following:

1. Issue **access tokens as signed JWTs**. Opaque access tokens are not
   supported.
2. Sign with an **asymmetric algorithm**: RS256/384/512, PS256/384/512, ES256,
   ES384 or EdDSA. Tokens signed with HMAC (`HS*`) are rejected.
3. Put a **custom audience** (`kanbot-api`) in the access token's `aud`, different
   from every client ID (see
   [why](#why-the-audience-must-differ-from-the-client-id)).
4. Put the user's roles or groups in an **array claim** that a dot-separated
   path can reach, such as `groups`, `roles` or `realm_access.roles`.
5. Serve OIDC discovery (`/.well-known/openid-configuration`) and the JWKS over
   **HTTPS**.
6. Support the **authorization code flow with PKCE (S256)** for confidential
   clients, and **refresh tokens**.
7. For machine clients, support the **client credentials** grant.

**Supported:** Keycloak, Authelia, Okta (custom authorization server) and
Microsoft Entra ID (single tenant, v2 tokens). **Not supported:** authentik,
whose access-token `aud` cannot be set apart from the ID token's (tested, see
[authentik](#authentik)).

Not supported: social logins whose access tokens are opaque or not meant for
third-party APIs (Google, Apple, GitHub), and any IdP that can only issue opaque
access tokens.

## What kanbot checks on every access token

- At most 16 KiB, three base64url segments (so opaque tokens are refused),
  and a header with `kid` and `alg` and without `crit`.
- Signature against the issuer's JWKS. The algorithm is taken from the JWK's
  `alg`, and a token whose header `alg` does not match it is rejected; a JWK
  without `alg` allows those of its key type (any RS or PS algorithm for an RSA
  key). `none` and `HS*` are always rejected.
- `iss` equals the configured issuer exactly.
- `aud` contains the configured audience.
- `exp`, `iss`, `aud` and `sub` are present.
- `exp` is in the future. If present, `nbf` and `iat` are not in the future,
  allowing 60 seconds of clock skew.
- `sub` (or the configured subject claim) is present.
- The roles claim resolves to an array that contains the admin role or the user
  role. Admins also count as users. Tokens with neither role are rejected
  (`403`).
- If `OIDC_ALLOWED_CLIENTS` is set, the client claim (`azp`, `client_id` or
  `cid`, whichever the IdP uses) must be in the list.

Refused tokens get `401` with `WWW-Authenticate: Bearer error="invalid_token"`
and never a reason; tokens without either role get `403`. The reason goes to
the `kanbot.auth.token.rejections` metric only.

The JWKS is fetched through discovery: the discovery document's `issuer` must
equal `OIDC_ISSUER` byte for byte, and its `jwks_uri` must be on the issuer's
origin or in `OIDC_JWKS_ALLOWED_ORIGINS`. Only signature keys are used: RSA of
at least 2048 bits, EC P-256 and P-384, and Ed25519; other keys are skipped.
The JWKS is cached and refreshed every `OIDC_JWKS_TTL`. An unknown key ID
triggers one refresh, at most once per second. If a refresh fails or returns
no usable keys, the last good key set is kept. The server starts even when the
IdP is unreachable: `/ready` answers `503`, and so do requests with a token,
until the keys load.

### Why the audience must differ from the client ID

An ID token's `aud` is the client ID it was issued to. If the API's audience
equals a client ID, an ID token for that client passes the audience check and
could be used as an access token. Kanbot refuses to start if `OIDC_AUDIENCE`
equals `OIDC_CLIENT_ID` or is listed in `OIDC_ALLOWED_CLIENTS`.

## Configuration

| Variable | Required | Meaning |
|---|---|---|
| `OIDC_ISSUER` | yes | Issuer URL. Must match the tokens' `iss` and the discovery document's `issuer` exactly. HTTPS only. |
| `OIDC_CLIENT_ID` | yes | Kanbot's confidential client, for example `kanbot`. Must differ from `OIDC_AUDIENCE`. |
| `OIDC_CLIENT_SECRET` (or `OIDC_CLIENT_SECRET_FILE`) | yes | Its secret. |
| `OIDC_AUDIENCE` | yes | Audience kanbot accepts, for example `kanbot-api`. |
| `OIDC_ROLES_CLAIM` | yes | Dot-separated path to the roles array, for example `groups`. |
| `OIDC_ADMIN_ROLE` | yes | Role value that grants platform admin, for example `kanbot-admin`. |
| `OIDC_USER_ROLE` | yes | Role value that grants access, for example `kanbot-user`. |
| `OIDC_SCOPES` | no | Scopes kanbot requests. Default `openid profile email offline_access`, plus whatever scope your IdP needs for the roles claim (for example `groups`). |
| `OIDC_SUBJECT_CLAIM` | no | Claim that identifies the user. Default `sub`. Use `oid` for Entra ID. |
| `OIDC_GROUPS_CLAIM` | no | Dot-separated path to the groups array, used to sync teams with identity provider groups and as `principal.groups` in authorization policies. Default: the value of `OIDC_ROLES_CLAIM`. Without it in a token, the user is in no synced team. |
| `OIDC_ALLOWED_CLIENTS` | no | Comma-separated client IDs whose tokens kanbot accepts, as bearer tokens and from sign-ins. It must include `OIDC_CLIENT_ID`. Default: any client. |
| `OIDC_JWKS_TTL` | no | Seconds between JWKS refreshes. Default `3600`. |
| `OIDC_JWKS_ALLOWED_ORIGINS` | no | Extra HTTPS origins allowed to serve the JWKS. |
| `OIDC_CA_FILE` | no | PEM bundle for an IdP with a private certificate authority. |
| `OIDC_DANGEROUSLY_ALLOW_INSECURE_HTTP` | no | Allows an `http://` issuer on a numeric loopback address. Development only. |
| `PUBLIC_URL` | yes | Kanbot's external base URL, for example `https://kanbot.example.com` (`http` only on `localhost` or a loopback address, for development: Safari refuses the session cookie over plain `http`, so test Safari over `https`). The callback URL is `<PUBLIC_URL>/auth/callback`. Register `<PUBLIC_URL>/` as an allowed post-logout redirect URI at the identity provider too. |
| `SESSION_ENCRYPTION_KEYS` (or `SESSION_ENCRYPTION_KEYS_FILE`) | yes | Comma-separated `<key id>:<base64 of 32 random bytes>` entries (for example `k1:$(openssl rand -base64 32)`), used to encrypt stored IdP tokens. The first encrypts and all decrypt: to rotate, put a new key first and drop the old one after `SESSION_ABSOLUTE_TIMEOUT`. |
| `SESSION_IDLE_TIMEOUT` | no | A session ends after this long without use (at most a tenth of it, and at most a minute, earlier). Default `7d`. |
| `SESSION_ABSOLUTE_TIMEOUT` | no | A session ends after this long regardless. Default `30d`. Sessions also end when the IdP refuses a refresh. |

## Clients to register at the IdP

| Client | Type | Grants | Redirect URI |
|---|---|---|---|
| `kanbot` | Confidential | Authorization code with PKCE (S256), refresh token | `https://<kanbot-host>/auth/callback` |
| `kanbot-automation` | Confidential, optional | Client credentials | none |

Tokens issued to these clients must have `aud` = `kanbot-api` and carry the
roles claim. Add one `kanbot-automation`-style client per script or service that
needs API access, so each can be revoked on its own.

**Recommended lifetimes:**

- **Access tokens:** 5 to 15 minutes. Bearer-token callers keep access until
  their token expires, even after being disabled at the IdP. Kanbot's own
  sessions can be revoked immediately.
- **Refresh tokens:** these decide how long a user stays signed in, because the
  backend refreshes access tokens in the background. Set them to match your
  sign-in policy.

**Roles:** create two groups or roles, `kanbot-admin` and `kanbot-user`, and
assign them to users. Keep them separate from OpenShell's roles, so admin rights
in one product don't imply admin rights in the other.

## Provider guides

Each guide lists only what was checked in the provider's own documentation.
Items marked **(verify)** could not be confirmed there and must be checked when
the provider is first tested with kanbot.

### Keycloak

Checked against Keycloak 26.8.2, and tested end to end with it: the local
stack runs it with the setup below (`backend/dev/keycloak/kanbot-realm.json`,
`backend/tests/keycloak.rs`).

- **Issuer:** `https://<host>/realms/<realm>`. Discovery is at
  `/realms/<realm>/.well-known/openid-configuration`.
- **Access tokens:** signed JWTs
  ([OIDC layers](https://www.keycloak.org/securing-apps/oidc-layers)).
  - Do not enable *lightweight access tokens* for kanbot's clients. Lightweight
    tokens leave out roles.
- **Client:** `kanbot` with client authentication on (confidential).
  - Enforce PKCE S256 with **PKCE Method** = `S256` (Advanced → Advanced
    settings; the client attribute `pkce.code.challenge.method`). Keycloak then
    refuses an authorization request without a challenge.
- **Audience:** add an **Audience** protocol mapper (`oidc-audience-mapper`) to a
  client scope assigned to kanbot's clients, with **Included Custom Audience** =
  `kanbot-api`
  ([protocol mappers](https://www.keycloak.org/admin-api/protocol-mappers)).
- **Roles:** either
  - realm roles, with `OIDC_ROLES_CLAIM=realm_access.roles` (the layout
    OpenShell documents), or
  - groups, through a **Group Membership** mapper with token claim name
    `groups`. Turn **Full group path** off: it defaults to on and would produce
    values like `/kanbot-admin`.
- **Scopes:** Keycloak refuses an authorization request with a scope it does
  not know (`invalid_scope`), so leave `groups` out of `OIDC_SCOPES` unless you
  created a client scope with that name; a mapper on the client puts the
  groups in the tokens anyway. Kanbot's default scopes
  (`openid profile email offline_access`) work.
- **Refresh tokens:** kanbot asks for `offline_access`, so users need the
  realm's `offline_access` role. Keycloak gives it to new users through the
  realm's default roles; users imported without them get `not_allowed`
  ("Offline tokens not allowed") at the token exchange.
- **Client credentials:** enable service accounts on `kanbot-automation`. The
  token is based on that client's service account.
- **Hostname:** set `hostname` to the public URL so the issuer never changes.
  Pods calling Keycloak inside the cluster must use the same issuer URL (see
  [Kubernetes](#kubernetes-notes)). `hostname-backchannel-dynamic` (default
  `false`) only changes backchannel endpoint URLs
  ([hostname](https://www.keycloak.org/server/hostname)).
- **Token exchange (RFC 8693):** supported and on by default
  (`token-exchange-standard:v2`). The requesting client must be confidential,
  and the subject token must include it in `aud`
  ([token exchange](https://www.keycloak.org/securing-apps/token-exchange)).
- **Logout:** RP-initiated logout at
  `/realms/<realm>/protocol/openid-connect/logout`.
- **Access token header `typ`:** the client setting **Use "at+jwt" as access
  token header type** (Advanced → Fine grain OpenID Connect configuration;
  the client attribute `access.token.header.type.rfc9068`, off by default:
  `JWT`). Kanbot accepts either.

### Authelia

Checked against Authelia 4.39.28. Authelia's OIDC provider is an **open beta**
feature.

- **Issuer:** Authelia's root URL, for example `https://auth.example.com`.
- **HTTPS:** `session.cookies[].authelia_url` must use `https://`, and the cookie
  domain must not be a special-use domain such as `localhost`. Authelia itself
  can listen on plain HTTP behind a TLS proxy, or terminate TLS with
  `server.tls`.
- **JWT access tokens are off by default.** Set `access_token_signed_response_alg`
  (or `access_token_signed_response_key_id`) on each kanbot client. Any value
  other than `none` makes access tokens RFC 9068 JWTs.
- **Audience:** list `kanbot-api` in each client's `audience`.
  - With the default `requested_audience_mode: explicit`, the client must
    request it with the `audience` parameter.
  - With `implicit`, a client that requests no audience gets all audiences it
    is allowed.
- **Roles:** the `groups` scope provides the `groups` claim. Copy it into the
  access token with a claims policy and set `OIDC_ROLES_CLAIM=groups`:

  ```yaml
  identity_providers:
    oidc:
      claims_policies:
        kanbot:
          access_token: ['groups', 'preferred_username', 'name']
      clients:
        - client_id: 'kanbot'
          client_secret: '$pbkdf2-sha512$...'  # hashed secret
          claims_policy: 'kanbot'
          access_token_signed_response_alg: 'RS256'
          audience: ['kanbot-api']
          require_pkce: true
          pkce_challenge_method: 'S256'
          scopes: ['openid', 'profile', 'email', 'groups', 'offline_access']
          grant_types: ['authorization_code', 'refresh_token']
          redirect_uris:
            - 'https://kanbot.example.com/auth/callback'
          consent_mode: 'pre-configured'
  ```

- **Redirect URIs:** must use `http` or `https` and are matched exactly. Custom
  URL schemes are not accepted. That is no problem for kanbot, whose only
  redirect URI is the backend's HTTPS callback.
- **Refresh tokens:** need the `offline_access` scope, and the authorization code
  flow then asks for explicit consent.
  - `consent_mode: pre-configured` (with `pre_configured_consent_duration`)
    remembers it.
  - Default lifespans are 1 hour for access tokens and 1 hour 30 minutes for
    refresh tokens. Set shorter access tokens and longer refresh tokens under
    `identity_providers.oidc.lifespans`.
- **Client credentials:** supported for confidential clients. If it is a client's
  only grant, `openid` and `offline_access` are not allowed.
- **Logout:** RP-initiated, front-channel and back-channel logout are **not
  supported**. Signing out of kanbot ends the kanbot session but not the
  Authelia session.
- **Token exchange:** listed as planned, not available.

### authentik

Checked against authentik 2026.8.6, and the audience tested with it. Some
facts come from authentik's source code, because the documentation has no
settings reference for them.

- **Issuer:** `https://<host>/application/o/<application-slug>/` by default
  (**Issuer mode**: one issuer per provider).
- **Access tokens:** always JWTs.
- **Signing key:** **select a signing key on the provider.** Without one,
  authentik signs with HS256 using the client secret and publishes no JWKS, and
  kanbot rejects those tokens.
- **Audience: limitation.**
  - `aud` is the provider's client ID. There is no audience setting.
  - RFC 8707 `resource` requests are rejected.
  - So ID tokens and access tokens share the same `aud`, which conflicts with
    [kanbot's audience rule](#why-the-audience-must-differ-from-the-client-id).
  - A custom scope mapping returning `aud` changes the ID token too. Tested
    with authentik 2026.8.6 (authorization code flow with PKCE, and client
    credentials): a mapping returning `"kanbot-api"` gives both tokens
    `aud: "kanbot-api"`, so the ID token no longer names the client; one
    returning `["kanbot", "kanbot-api"]` gives both tokens both audiences, so
    an ID token would pass as an access token. Either way the two tokens
    cannot be told apart by audience.
  - Access tokens carry `azp`; ID tokens do not.
  - **authentik is not supported**, until it can set the access token's
    audience on its own.
- **Roles:** the default `profile` scope mapping returns the user's group names
  in `groups`. They appear in the access token only while **Include claims in
  id_token** is on (the default).
- **Grant types:** a provider created through the API in 2026.8 has an empty
  list of allowed grant types and refuses every request ("Invalid grant_type
  for provider"); allow `authorization_code` and `refresh_token`.
- **PKCE:** supported but not enforced. When the method is omitted it defaults to
  `plain`. Kanbot always sends S256.
- **Client credentials:** supported. authentik creates a service account per
  provider.
- **Subject mode:** defaults to a hashed user ID.
- **Logout:** RP-initiated logout at
  `/application/o/<application-slug>/end-session/`.
- **Token exchange:** added in 2026.8.

### Okta

Checked against Okta's developer documentation.

- **Use a custom authorization server.** Tokens from Okta's *org* authorization
  server are only for Okta's own APIs and must not be validated by your
  services.
  - Custom authorization servers need the **API Access Management** add-on in
    production.
  - The free Integrator org has a preconfigured `default` server.
- **Issuer:** `https://<okta-domain>/oauth2/<authorization-server-id>`, or
  `.../oauth2/default`.
- **Audience:** the authorization server's **Audience** setting becomes `aud`.
  Set it to `kanbot-api`.
- **Client:** a web application integration (confidential) with PKCE.
- **Roles:** add a `groups` claim on the custom authorization server (value type
  *Groups*, included in the *Access Token*, with a group filter). Set
  `OIDC_ROLES_CLAIM=groups`.
  - If more than 100 groups match the filter, the token request fails.
- **Claims:** access tokens carry `cid` (client ID), `uid` (user ID), `scp` and
  `sub`. There is no `azp`. If you set `OIDC_ALLOWED_CLIENTS`, kanbot reads
  `cid`.
- **Signing:** tokens are always signed with RS256.
- **Client credentials:** needs a custom authorization server and at least one
  custom scope. It has no user context.
- **Logout:** RP-initiated logout at `/oauth2/v1/logout` on the org server
  (verify the path for custom authorization servers).
- **Token exchange:** supported (*On-Behalf-Of Token Exchange*, RFC 8693).

### Microsoft Entra ID

Checked against Microsoft Learn.

- **Two app registrations:**
  - an **API** registration that represents `kanbot-api`, and
  - a **web** registration for the `kanbot` client (confidential, with a client
    secret or certificate).

  A token an app requests for itself has `aud` equal to its own client ID, which
  kanbot's audience rule rejects. That is why the API needs its own
  registration.
- **Use v2 access tokens.** Set `api.requestedAccessTokenVersion` to `2` in the
  API registration's manifest. With the default (`null`, meaning 1), tokens are
  v1: `aud` and `iss` differ from v2, and `iss` does not match the v2 discovery
  document.
- **Issuer:** `https://login.microsoftonline.com/<tenant-id>/v2.0`. Use a single
  tenant. The multi-tenant `common` issuer needs per-tenant substitution, which
  kanbot does not do.
- **Audience:** in v2 tokens, `aud` is always the **API registration's client ID**
  (a GUID). Set `OIDC_AUDIENCE` to that GUID. Kanbot requests a scope of the API
  (for example `api://<api-client-id>/access`).
- **Roles:** define app roles on the API registration and assign them. They
  appear in the `roles` claim (`OIDC_ROLES_CLAIM=roles`).
  - App roles assigned to a group of service principals do not produce a
    `roles` claim.
  - Avoid the `groups` claim: above 200 groups it is replaced by an overage
    indicator.
- **Subject:** `sub` is pairwise, different for the same user in each
  application. Set `OIDC_SUBJECT_CLAIM=oid`, which is stable across applications
  within a tenant.
- **Signing:** RS256. The JWKS entries have no `alg`, so kanbot accepts the RSA
  algorithms for those keys.
- **One resource per token:** a token covers a single API. Scopes for several
  resources in one token request are an error.
- **Client credentials:** request `<api-app-id-uri>/.default`. Roles come from
  application permissions.
- **On-behalf-of:** Entra's OBO flow uses the `jwt-bearer` grant, not RFC 8693.
- **Logout:** RP-initiated logout is supported (`end_session_endpoint`,
  `post_logout_redirect_uri`).

## OpenShell alignment

[OpenShell](https://docs.nvidia.com/openshell/kubernetes/access-control)
validates JWT access tokens the same way kanbot validates bearer tokens. To run
both against one IdP:

- Use the **same issuer**.
- Use **different audiences**: `kanbot-api` for kanbot, and a dedicated one such
  as `openshell-gateway` for OpenShell. Do not keep OpenShell's default audience
  `openshell-cli`: it is also the CLI's client ID, so ID tokens issued to the CLI
  would likely pass the gateway's audience check.
- Use the **same roles claim** with separate role names (`kanbot-admin` and
  `kanbot-user`, `openshell-admin` and `openshell-user`).
- Register OpenShell's CLI as its own public client (`openshell-cli`), with
  PKCE, a loopback redirect and the device grant. With Authelia, which matches
  redirect URIs exactly, give the CLI a fixed `OPENSHELL_CALLBACK_PORT` or use
  `OPENSHELL_NO_BROWSER=1` (device flow).

```toml
[openshell.gateway.oidc]
issuer = "https://auth.example.com"
audience = "openshell-gateway"
roles_claim = "groups"
admin_role = "openshell-admin"
user_role = "openshell-user"
```

OpenShell quirks to know:

- It does not check `azp`. Any client of the issuer that can obtain a token with
  OpenShell's audience is accepted. Restrict at the IdP which clients may request
  that audience.
- If both of OpenShell's role names are empty, every authenticated user becomes
  a platform admin. Always set both.
- It accepts only JWT access tokens and does not support token introspection.
  Machine access uses `client_credentials`.
- Its Kubernetes deployment is marked experimental. Pin its chart version.

To have kanbot keep OpenShell workspace members in line with its
organizations, see [openshell.md](openshell.md).

## Kubernetes notes

- **One issuer URL everywhere.** Browsers, kanbot's pods and OpenShell's pods
  must all reach the IdP at the same URL, because `iss` is compared exactly. Use
  a hostname that resolves both inside and outside the cluster.
- **Private CA:** mount the same CA bundle into kanbot (`OIDC_CA_FILE`) and
  OpenShell (`server.oidc.caConfigMapName`).
- **No ingress-level OIDC.** Don't put an OIDC-enforcing proxy in front of the
  kanbot API or the OpenShell gateway. Both handle authentication themselves, and
  a redirect-based proxy breaks native apps, the CLI and machine clients.
- **`TRUSTED_PROXIES`:** list the ingress controller's addresses (or the pod
  network it connects from), so kanbot reads the client address from
  `X-Forwarded-For`. Without it, every request seems to come from the ingress:
  the per-IP limits then count all users together, and authorization policies
  that use `context.ip` see the ingress. Never list a range that clients can
  send from: they could then choose their own address.
- **Rate limits multiply with replicas.** Limits are kept in memory per
  instance, so N replicas allow N times each `RATE_LIMIT_*` value, and a client
  over its limit on one pod is not on another. Size them per pod.
- **Secrets:** pass the client secret and the session keys as files
  (`OIDC_CLIENT_SECRET_FILE`, `SESSION_ENCRYPTION_KEYS_FILE`) from a Secret.
  Every replica needs the same session keys, or sessions created on one pod
  cannot be used on another.
- **Deploy order:** run `kanbot-backend migrate` (a Job) before rolling out a
  new version; pods report not ready until the migrations are applied.
- **Session key rotation:** put the new key first in
  `SESSION_ENCRYPTION_KEYS` on every replica, then remove the old one once
  `SESSION_ABSOLUTE_TIMEOUT` has passed.

## Changing the issuer or the subject claim

Kanbot identifies a user by the pair (issuer, subject): the value of
`OIDC_ISSUER` and of the claim `OIDC_SUBJECT_CLAIM` names. Changing either one
**detaches every existing user**:

- the next sign-in creates a new user, with no organization admin rights and no
  manual team memberships; teams synced with an identity provider group fill
  up again as users sign in;
- the old users stay in the database, with their memberships, admin rights and
  audit history, but nobody can sign in as them;
- existing kanbot sessions end on their next request: their stored tokens no
  longer resolve to the session's user.

So pick both before going live, and treat a change as a migration: move the
memberships and admin rights to the new users with SQL (by matching email or
display name), or recreate them through the API. Moving to another identity
provider is such a change even when the users are the same people.

Changing `OIDC_ROLES_CLAIM`, `OIDC_GROUPS_CLAIM` or the role names takes effect
on the next request of each user: platform roles and synced teams follow the
tokens, nothing has to be migrated.

## Native apps and TLS

Native apps ask for the server URL on first launch and only connect over HTTPS.
The server certificate must be trusted by the device:

- Android apps do not trust user-installed certificate authorities, and the
  kanbot app does not add any;
- iOS and macOS trust a private CA only once it is installed and, on iOS,
  enabled for full trust in the settings;
- the sign-in opens in the system browser, which must trust the certificate of
  kanbot and of the identity provider too.

So use publicly trusted certificates, for example from Let's Encrypt (a DNS
challenge works for homelab servers that are not reachable from the internet),
for kanbot and for the identity provider. The web app has no such limit: the
browser decides.

## Local development

The local stack (`backend/compose.yaml`, which pins the versions) runs Authelia
next to Postgres at `https://auth.kanbot.internal:9443`, configured as described
above (`backend/dev/authelia/`), and Keycloak at
`https://auth.kanbot.internal:8443/realms/kanbot` (`backend/dev/keycloak/`),
the second identity provider of the end-to-end tests. Both use the same
hostname, so one `/etc/hosts` entry serves both. `backend/dev/auth-setup.sh` generates its
certificates (from a local certificate authority), secrets and signing key.
Authelia rejects special-use domains such as `localhost` for its cookie
domain, so the stack uses `kanbot.internal` (checked: Authelia 4.39.28
accepts it), mapped to loopback in `/etc/hosts`:

```
127.0.0.1 auth.kanbot.internal
```

Both have the same development-only users, each with the
password `<username>-dev-password`: `alice` in `kanbot-admin`, `bob` in
`kanbot-user`, `carol` in no kanbot group, and `dave` in `kanbot-user` and
`contractors`. The `kanbot` client's development-only secret is
`kanbot-dev-client-secret`. `backend/AGENTS.md` has the commands.
