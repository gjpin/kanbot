# kanbot

## Documentation

- [Authentication with OpenID Connect](docs/oidc.md): how kanbot uses an external OIDC identity provider, and how to set up Keycloak, Authelia, Okta or Microsoft Entra ID (authentik is not supported: it cannot give access tokens their own audience).
- [Authorization](docs/authorization.md): organizations, teams and their access, and how deployers add Cedar `forbid` policies.
- [OpenShell integration](docs/openshell.md): linking organizations to OpenShell workspaces, whose members kanbot keeps in sync.

## Development

- [Development container](.devcontainer/README.md): every tool the checks need, with Postgres and the local Authelia.
