# Local Keycloak

The second identity provider of the local stack (`compose.yaml`), for the
end-to-end tests against Keycloak (`tests/keycloak.rs`). DEVELOPMENT ONLY.

- `kanbot-realm.json` is imported when the container starts: the realm
  `kanbot`, the confidential client `kanbot` (dev-only secret
  `kanbot-dev-client-secret`, PKCE S256 enforced), a **Group Membership**
  mapper (`groups`, full path off) and an **Audience** mapper adding
  `kanbot-api` to access tokens, and the same dev users as Authelia, each
  with the password `<username>-dev-password`: `alice` (`kanbot-admin`), `bob`
  (`kanbot-user`), `carol` (no kanbot group) and `dave` (`kanbot-user`,
  `contractors`).
- Issuer: `https://auth.kanbot.internal:8443/realms/kanbot`, the same dev
  hostname as Authelia on another port, with the certificate from
  `dev/auth-setup.sh`.
- Nothing persists (`--db=dev-mem`): the realm is imported again on every
  start.
