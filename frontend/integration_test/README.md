# End-to-end tests

`sign_in_test.dart` signs in on Linux desktop against the local stack, the
way a person would: the app opens the server's `/auth/login` in the system
browser, the browser signs in at Authelia and is redirected to the app's
loopback address with a one-time code, and the app redeems it for a session
token kept in the platform's secret store (`docs/plan/auth.md` §5.8).

No person is there to type a password, so `run_linux.sh` registers a
stand-in default browser for the run: `cargo run --example dev-token -- alice
--sign-in <url>` (`backend/examples/dev_token.rs`) follows the redirects and
signs `alice` in with her documented dev password. Everything else is the
real app, backend and identity provider.

## Running it

On Linux, with the frontend's build dependencies (`frontend/AGENTS.md` §10)
plus `xvfb`, `dbus` and `gnome-keyring`:

```sh
# The local stack and the backend (backend/AGENTS.md)
cd backend
sh dev/auth-setup.sh
docker compose up -d --wait
set -a; . dev/dev.env; set +a
sqlx migrate run
cargo build --example dev-token
cargo run &

# The test
sh ../frontend/integration_test/run_linux.sh
```

CI runs it in the `linux-sign-in` job of `.github/workflows/frontend.yml`.
