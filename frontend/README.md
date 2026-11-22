# kanbot app

The Flutter client of the kanbot API, for Android, iOS, web, macOS, Linux and
Windows. It is built with [shad](https://shad.serverpod.dev/) and talks to
the backend through a client generated from `../backend/openapi.json`.

- Rules and every check to run: [`AGENTS.md`](AGENTS.md).
- Sign-in: [`../docs/oidc.md`](../docs/oidc.md); the end-to-end test:
  [`integration_test/README.md`](integration_test/README.md).

## Running it

With the backend running (`../backend/AGENTS.md`):

```sh
flutter run -d macos   # or linux, windows; a native app asks for its server
dart run tool/build_web.dart   # the web app, served by the backend (WEB_DIR)
```

`--dart-define=API_BASE_URL=http://localhost:3000` sets the server a native
app suggests on first launch. The web app always talks to the server it is
loaded from.
