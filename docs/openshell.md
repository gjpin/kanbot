# OpenShell integration

Kanbot can keep the members of [OpenShell](https://docs.nvidia.com/openshell)
workspaces in line with its organizations. A platform admin links an
organization to one workspace; from then on kanbot syncs the workspace's
members, one way, kanbot → OpenShell:

| In kanbot | In the workspace |
|---|---|
| an admin of the organization | `admin` |
| a member of a team linked with `write` | `user` |
| anyone else (readers, disabled accounts, users of another issuer) | not added; removed if kanbot added them |

The integration is off unless `OPENSHELL_GATEWAY_URL` is set. Supported
OpenShell versions are listed in
[`backend/openshell-api/README.md`](../backend/openshell-api/README.md).

## How the sync works

- Members are identified by their OIDC subject, so kanbot and OpenShell must
  use the **same issuer and subject claim** ([oidc.md](oidc.md#openshell-alignment)).
- Kanbot changes only the members **it added** (table `openshell_members`).
  Someone added in OpenShell another way is left alone, even if kanbot would
  have added them too, and is never removed by kanbot.
- A role change removes the member and adds them back with the new role
  (OpenShell has no call to change a role).
- When an organization is unlinked or deleted, the next sync removes the
  members kanbot added to its workspace.
- The sync runs every 5 minutes and right after a link changes. It stops at
  the first failure and logs it (`openshell membership sync failed`); the next
  run picks up from there. Each run that added or removed members logs the
  counts (`openshell membership synced`); a run that changed nothing logs
  nothing.
- A workspace can be linked to only one organization.

The workspace must exist: kanbot does not create workspaces. When a platform
admin links one, kanbot checks with the gateway that it exists and that the
admin may see it.

## Tokens

Kanbot never sends the gateway a token that is also valid for kanbot. Every
token it obtains must carry `OPENSHELL_AUDIENCE` and must not carry
`OIDC_AUDIENCE`; any other is refused and the call fails. The configuration
refuses equal audiences.

- **Sync (kanbot's own calls):** a service account, `client_credentials` with
  `OPENSHELL_CLIENT_ID` and its secret (`client_secret_basic`). The token is
  cached until 30 seconds before it expires. Set `OPENSHELL_TOKEN_SCOPE` if your
  identity provider needs a scope to issue the gateway's audience (Microsoft
  Entra ID: `api://<gateway app>/.default`).
- **Linking a workspace (a call a user starts):** with
  `OPENSHELL_TOKEN_EXCHANGE=true`, kanbot exchanges the user's own access token
  for one with the gateway's audience (RFC 8693), so OpenShell checks the user's
  own access to the workspace. Use it where the identity provider supports it
  (Keycloak, Okta, authentik 2026.8+). Otherwise the service account's token is
  used.

### What the service account needs in OpenShell

Adding and removing members needs workspace role `admin` in each linked
workspace (or OpenShell's platform admin role) and, when the gateway enforces
scopes, the scope `workspace:write`. Give the service account those, for
example by making its subject an admin of each workspace you link.

At the identity provider:

- Register a confidential client for kanbot's OpenShell calls (it can be a
  different client from `OIDC_CLIENT_ID`), allowed to use `client_credentials`
  and, with token exchange, the token-exchange grant.
- Make sure its tokens carry the gateway's audience, and **only** that one.
- OpenShell does not check `azp`: restrict which clients may request its
  audience ([oidc.md](oidc.md#openshell-alignment)).

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `OPENSHELL_GATEWAY_URL` | unset (off) | The gateway's gRPC endpoint, `https://` only |
| `OPENSHELL_AUDIENCE` | required | The gateway's audience, for example `openshell-gateway`; must differ from `OIDC_AUDIENCE` |
| `OPENSHELL_CLIENT_ID` | required | Kanbot's client for gateway tokens |
| `OPENSHELL_CLIENT_SECRET` or `OPENSHELL_CLIENT_SECRET_FILE` | required | Its secret |
| `OPENSHELL_TOKEN_SCOPE` | none | `scope` to request, if the identity provider needs one |
| `OPENSHELL_TOKEN_EXCHANGE` | `false` | Exchange the user's token for calls a user starts |
| `OPENSHELL_CA_FILE` | none | PEM certificates trusted for the gateway, besides the system roots |

## API

- `PUT /organizations/{id}/openshell_workspace` with `{"workspace": "<name>"}`
  links the organization. `422` with `/workspace` `not_found` if the workspace
  does not exist; `409` if another organization links it, or the server has no
  OpenShell integration; `403` if OpenShell refuses the user.
- `DELETE /organizations/{id}/openshell_workspace` unlinks it.
- `GET /organizations/{id}` returns `openshell_workspace`, and the permission
  `link_openshell_workspace` when the caller may link it and the integration is
  on.

Only platform admins may link or unlink (Cedar action `linkOpenShellWorkspace`,
no built-in permit, [authorization.md](authorization.md)). Both are recorded in
the audit log (`organization.openshell_linked`,
`organization.openshell_unlinked`).
