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

Deployer policies ([authorization.md](authorization.md)) apply: someone Cedar
does not allow `write` on the organization is not added, and an admin Cedar
does not allow `manageOrganization` is only a `user`. The sync decides without
a request: `context.via` is `"sync"` and `context.ip` is `0.0.0.0`, so a policy
that allows only some networks keeps the sync out unless it allows `"sync"` on
purpose. Its groups are those of the user's last token with the groups claim.

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
- Kanbot records a member before adding them, so a crash or a failed call
  never leaves a member it added unrecorded (and so never removed).
- When an unlinked workspace no longer exists in OpenShell, kanbot forgets
  what it had recorded there.
- The sync runs every 5 minutes, and soon after anything it reads changes:
  database triggers notify every instance (Postgres `LISTEN`/`NOTIFY`) when
  admins, team links, team members, a link, or a user's groups, role or
  disabled state change. Runs are at least 5 seconds apart.
- One instance syncs at a time (a Postgres advisory lock); the others skip.
- A workspace that fails is logged (`a workspace could not be synced`) and
  skipped; the others still sync, and a failed run is retried after 30
  seconds. Each run that added, removed or failed logs the counts
  (`openshell membership synced`); the metrics
  `kanbot.openshell.sync.members` and `kanbot.openshell.sync.failures` count
  them.
- A workspace can be linked to only one organization.
- **Kanbot learns about groups and roles when users use kanbot.** Someone
  removed from an identity provider group, or who lost their kanbot role,
  stays in the workspace until they next sign in or call the API, since kanbot
  only sees their groups in their tokens. To remove someone at once, remove
  them from the team or organization in kanbot, or disable them.

The workspace must exist: kanbot does not create workspaces. Workspace names
are Kubernetes-style names (lowercase letters, digits, `-` and `.`, at most 253
characters). When a platform admin links one, kanbot asks the gateway:

- with `OPENSHELL_TOKEN_EXCHANGE=true`, as the admin (their exchanged token),
  who must be an **admin of the workspace** in OpenShell: seeing it is not
  enough, since the sync then makes the organization's admins workspace admins;
- otherwise as the service account, whether it exists: any platform admin can
  then link any workspace the service account can see.

Either way, the sync can change members only where the service account is a
workspace admin (below). That grant is the real boundary of what kanbot can
do in OpenShell.

## Tokens

Kanbot never sends the gateway a token that is also valid for kanbot. Every
token it obtains is verified like any access token (signature with the identity
provider's keys, issuer, expiry), must carry `OPENSHELL_AUDIENCE` and must not
carry `OIDC_AUDIENCE`; any other is refused and the call fails. An exchanged
token must name the same subject as the user's. The configuration refuses equal
audiences, and an `OPENSHELL_CLIENT_ID` equal to either audience (ID tokens
issued to it would pass as access tokens).

- **Sync (kanbot's own calls):** a service account, `client_credentials` with
  `OPENSHELL_CLIENT_ID` and its secret (`client_secret_basic`). The token is
  cached until 30 seconds before it expires. Set `OPENSHELL_TOKEN_SCOPE` if your
  identity provider needs a scope to issue the gateway's audience (Microsoft
  Entra ID: `api://<gateway app>/.default`).
- **Linking a workspace (a call a user starts):** with
  `OPENSHELL_TOKEN_EXCHANGE=true`, kanbot exchanges the user's own access token
  for one with the gateway's audience (RFC 8693), so OpenShell checks the user's
  own access to the workspace. Use it where the identity provider supports it
  (Keycloak, Okta). Otherwise the service account's token is used. An identity
  provider refusing the exchange is `403`.

### What the service account needs in OpenShell

Adding and removing members needs workspace role `admin` in each linked
workspace (or OpenShell's platform admin role) and, when the gateway enforces
scopes, the scope `workspace:write`. Make the service account an admin of
**only** the workspaces kanbot should manage, and avoid OpenShell's platform
admin role for it: any platform admin in kanbot can link a workspace, and
the sync then makes the organization's admins workspace admins there.

At the identity provider:

- Register a confidential client for kanbot's OpenShell calls (it can be a
  different client from `OIDC_CLIENT_ID`), allowed to use `client_credentials`
  and, with token exchange, the token-exchange grant.
- Make sure its tokens carry the gateway's audience, and never kanbot's
  (other audiences are tolerated, but best avoided).
- OpenShell does not check `azp`: restrict which clients may request its
  audience ([oidc.md](oidc.md#openshell-alignment)).

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `OPENSHELL_GATEWAY_URL` | unset (off) | The gateway's gRPC endpoint, `https://` only |
| `OPENSHELL_DANGEROUSLY_ALLOW_INSECURE_HTTP` | `false` | Allows `http://` on a numeric loopback host. Tests only |
| `OPENSHELL_AUDIENCE` | required | The gateway's audience, for example `openshell-gateway`; must differ from `OIDC_AUDIENCE` |
| `OPENSHELL_CLIENT_ID` | required | Kanbot's client for gateway tokens; must differ from both audiences |
| `OPENSHELL_CLIENT_SECRET` or `OPENSHELL_CLIENT_SECRET_FILE` | required | Its secret (surrounding whitespace, such as a file's final newline, is ignored) |
| `OPENSHELL_TOKEN_SCOPE` | none | `scope` to request, if the identity provider needs one |
| `OPENSHELL_TOKEN_EXCHANGE` | `false` | Exchange the user's token for calls a user starts |
| `OPENSHELL_CA_FILE` | none | PEM certificates trusted for the gateway, besides the system roots (enough on its own in an image without them). A file without a valid certificate stops startup |

## API

- `PUT /organizations/{id}/openshell_workspace` with `{"workspace": "<name>"}`
  links the organization. `422` with `/workspace` `not_found` if the workspace
  does not exist (`invalid` for a name that cannot be one); `409` if another
  organization links it, or the server has no OpenShell integration; `403` if
  the identity provider or OpenShell refuses the user, or (with token
  exchange) they are no admin of the workspace.
- `DELETE /organizations/{id}/openshell_workspace` unlinks it.
- `GET /organizations/{id}` returns `openshell_workspace`, and the permission
  `link_openshell_workspace` when the caller may link it and the integration is
  on.

Only platform admins may link or unlink (Cedar action `linkOpenShellWorkspace`,
no built-in permit, [authorization.md](authorization.md)). Both are recorded in
the audit log (`organization.openshell_linked`,
`organization.openshell_unlinked`).
