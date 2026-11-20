# Migrations

Schema changes, applied in order by `kanbot-backend migrate` (see
`backend/AGENTS.md`). sqlx embeds every `<VERSION>_<DESCRIPTION>.sql` file here
into the binary at compile time; other files, like this one, are ignored.

- Add a migration with `sqlx migrate add <description>`, never by hand-picking
  a version number.
- Never edit, rename or delete a migration once it is committed. CI rejects
  pull requests that do. Fix mistakes with a new migration.
- The app's `/ready` endpoint reports `503` until every migration here has
  been applied with a matching checksum.
