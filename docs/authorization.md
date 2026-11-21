# Authorization

Who may do what in kanbot. Authentication (who someone is) is in
[`oidc.md`](oidc.md); this document starts from a signed-in user.

Kanbot decides with [Cedar](https://www.cedarpolicy.com), in-process. Grants are
**data** (organizations, teams, links, admins), never custom policies. Built-in
`permit` policies turn that data into access. Deployers can add **`forbid`**
policies to narrow it further, never to widen it.

## The model

```
organization ◄──(read | write)── team ◄──(member | maintainer)── user
      ▲
      └── admins (users)
```

- **Organizations** are what kanbot's features belong to. A fresh instance has
  one, **Default**, which cannot be deleted.
- **Teams** belong to the whole instance, not to an organization. A user can be
  in several teams, and a team can be linked to several organizations.
- **Access is on the link**, not on the membership. A team linked to an
  organization with `read` lets its members read it; `write` lets them read and
  write. A user's access to an organization is the highest among their teams'
  links to it.
- **Organization admins** manage an organization: its name, its admins and which
  teams are linked at what level. They cannot change a team's members.
- **Team maintainers** manage a team: its name and its members. They cannot
  link it to an organization.
- **Platform roles** come from the identity provider's roles claim
  (`OIDC_ADMIN_ROLE`, `OIDC_USER_ROLE`). Platform admins may do everything.

### Built-in permissions

| Action | Resource | Allowed to |
|---|---|---|
| `read` | organization | members of a team linked with `read` or `write`; its admins |
| `write` | organization | members of a team linked with `write`; its admins |
| `manageOrganization` (rename) | organization | its admins |
| `manageOrganizationAdmins` | organization | its admins |
| `manageTeamLinks` | organization | its admins |
| `deleteOrganization` | organization | platform admins (never the Default organization) |
| `viewTeam` (see it and its members) | team | its members; admins of any organization |
| `manageTeam` (rename, delete) | team | its maintainers |
| `manageTeamMembers` | team | its maintainers (not for a synced team) |
| `setTeamIdpGroup` | team | platform admins |
| `createOrganization` | platform | platform admins |
| `createTeam` | platform | admins of any organization (the creator becomes maintainer) |
| `searchUsers` (`GET /users`) | platform | admins of any organization; maintainers of any team |
| `viewAudit` (`GET /audit`) | platform | platform admins |

Platform admins are allowed every action above. Someone who may not see an
organization or team gets `404` for it, whatever they try; someone who may see
it but not do this gets `403`.

The app asks the server what the user may do (`/me`, `GET /organizations/{id}`,
`GET /teams/{id}` list `permissions`) and hides the other controls. The server
checks every request anyway.

### Teams synced with an identity provider group

A platform admin can set a team's `idp_group`. The team's members are then the
users whose groups claim (`OIDC_GROUPS_CLAIM`, by default the roles claim)
contains that group:

- Setting the group removes the team's current members. Users join as they
  sign in or make a request: kanbot checks every authenticated request and
  writes only when something changed.
- Synced memberships are read-only: changing or removing one, or adding anyone
  to a synced team, is `409 conflict`.
- Clearing the group removes the synced members; the team can then be managed
  by hand again.
- Synced members are plain members. A synced team has no maintainers, so only
  platform admins can rename or delete it.

### The audit log

Every change to organizations and teams is recorded in the same transaction as
the change: who, what (`organization.team_linked`, `team.member_set`, ...),
which organization or team, the IDs of the policies that allowed it, and
details made of IDs and enumerated values only (never names). Platform admins
read it with `GET /audit`, newest first.

## Deployer policies

`AUTHZ_POLICY_FILE` names a file of Cedar policies that kanbot loads at startup,
next to the built-in ones. The server refuses to start if the file:

- contains a `permit` (only `forbid` is allowed);
- contains a template;
- has a policy without an `@id("...")` annotation, or two with the same one;
- does not parse, or does not validate against kanbot's schema (strict mode).

A `forbid` always wins over a `permit`, platform admins included. Each policy's
ID in the audit log and the logs is `deployer.<@id>`; built-in ones are
`builtin.<@id>`. Denials are logged with the user's ID, the action and the
policy IDs.

### Why `forbid` only

- A custom policy can never widen access by mistake: grants stay in the data,
  where the app shows them.
- Lists stay correct. `GET /organizations` and `GET /teams` first select, with
  SQL, every candidate the built-in permits could allow, then ask Cedar about
  each. A `forbid` can only remove candidates; a custom `permit` could allow one
  the SQL never selected.

### What a policy can use

Everything is in the `Kanbot` namespace. The schema is
[`backend/src/authz/schema.cedarschema`](../backend/src/authz/schema.cedarschema).

| | |
|---|---|
| `principal` (`Kanbot::User`) | `platformRole` (`"admin"` or `"user"`), `groups` (set of strings, from `OIDC_GROUPS_CLAIM`), `clientId` (optional: the token's `azp`, `client_id` or `cid`; test with `has`), `organizationAdmin` and `teamMaintainer` (booleans). `principal in Kanbot::Team::"<id>"` tests membership |
| `resource` | `Kanbot::Organization` (`readers`, `writers`, `admins`), `Kanbot::Team` (`maintainers`) or `Kanbot::Platform::"kanbot"` |
| `action` | `Kanbot::Action::"<name>"`, the names in the table above |
| `context` | `via` (`"web"`, `"native"` or `"bearer"`: session cookie, native app session, or an identity provider's access token) and `ip` (the client address, `TRUSTED_PROXIES` applied) |

Write policies about the principal, the resource and the context. Only the
entities a decision needs are loaded, so a policy that refers to some other
entity by ID (`Kanbot::Team::"<id>".maintainers`) cannot read its attributes. A
policy that fails to evaluate is skipped, as Cedar does, and for a `forbid` that
means it does not deny: the failure is logged as a warning with the policy ID.

IDs are the UUIDs the API returns.

### Examples

These are also in
[`backend/src/authz/examples.cedar`](../backend/src/authz/examples.cedar), where
a test checks that kanbot accepts them.

Contractors may read, never write:

```cedar
@id("contractors-read-only")
forbid (principal, action == Kanbot::Action::"write", resource)
when { principal.groups.contains("contractors") };
```

Administration only from the office network, and never with a bare access
token:

```cedar
@id("admin-from-the-office")
forbid (
  principal,
  action in [
    Kanbot::Action::"manageOrganizationAdmins",
    Kanbot::Action::"manageTeamLinks",
    Kanbot::Action::"setTeamIdpGroup",
    Kanbot::Action::"deleteOrganization"
  ],
  resource
)
unless { context.ip.isInRange(ip("10.0.0.0/8")) && context.via != "bearer" };
```

Scripts (a CI client) may read but change nothing:

```cedar
@id("ci-reads-only")
forbid (principal, action, resource)
when { principal has clientId && principal.clientId == "kanbot-ci" }
unless { action == Kanbot::Action::"read" };
```

Freeze one organization, admins included:

```cedar
@id("freeze-legacy")
forbid (
  principal,
  action in [Kanbot::Action::"write", Kanbot::Action::"manageTeamLinks"],
  resource == Kanbot::Organization::"6f1c2b8e-9a43-4a57-9d2e-0c6b3f1d2a10"
);
```

The local stack loads [`backend/dev/policies.cedar`](../backend/dev/policies.cedar),
which makes the `contractors` group (the dev user `dave`) read-only.

## For developers

- Every feature that touches organization data asks `authz` (`backend/AGENTS.md`
  §3b): `authz::service::require` before a change, `can` or `decisions` to show
  what is allowed, `visible_organizations` or `visible_teams` for lists. Never
  write a role check by hand.
- A new action goes in the schema, a built-in policy and `authz::model::Action`,
  with tests of what it allows and denies.
- Grant through data. If a feature seems to need a new kind of grant, add it to
  the model (an entity, an attribute, a link) and a built-in policy.
