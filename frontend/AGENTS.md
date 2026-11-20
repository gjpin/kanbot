# AGENTS.md (frontend)

Rules for `frontend/`, a **Flutter** app that targets Android, iOS, web, macOS,
Linux and Windows. App code lives in `lib/`, tests in `test/`. These rules add to
the [root `AGENTS.md`](../AGENTS.md). Follow both.

CI (`.github/workflows/frontend.yml`) enforces formatting, `flutter analyze` and
`flutter test`. The analyzer enforces many of the rules below (§11). The rest
cannot be checked automatically, so following them is your responsibility.

Verified against **Flutter 3.50.0 / Dart 3.14.0** and `shad` 1.0.2 as of
2026-11-20. Re-check this file and the skills (§13) after each Flutter stable or
`shad` major upgrade.

## 0. Precedence

- These rules **override** the skills (§13) and their code examples. The skills
  in `.agents/skills/` are maintained to follow this file; if one disagrees with
  it, follow this file and fix the skill.
- The root `AGENTS.md` still applies, including its rules on dependencies and
  exceptions.
- If a rule blocks you, stop and report it. Do not work around it.

## 1. Never weaken the checks

- Do not edit `analysis_options.yaml`, `pubspec.yaml` dependency constraints,
  `l10n.yaml`, CI config, `android/`, `ios/`, `macos/` or `web/` platform config
  unless the task explicitly asks for it.
- No `// ignore:`, `// ignore_for_file:`, or `# ignore:` in hand-written code.
  The only exception is generated code (`*.g.dart`, `*.freezed.dart`,
  `*.mocks.dart`, `lib/src/third_party/**`), which is excluded via
  `analyzer: exclude:` instead. There is no inline exception form in this
  directory: if a diagnostic seems wrong, stop and ask a maintainer (see
  [Exceptions](../AGENTS.md#exceptions)).
- No `// coverage:ignore-line`, `coverage:ignore-start/end`, or
  `coverage:ignore-file`. If code is not covered, write a test.
- Do not downgrade analyzer errors (for example `invalid_assignment: warning`).
- Do not use `late` to silence a "non-nullable field must be initialized" error.
  Initialize the field, make it nullable and handle `null`, or restructure.
  `late` is allowed only when initialization is guaranteed in the same class
  (for example in `initState`) and a test covers that path.
- No `!` null assertions on values that come from outside the program: route
  parameters, JSON, platform channels, storage, `snapshot.data`, map lookups.
  Handle the `null` case explicitly.
- Do not use `assert` for validation. Asserts are removed in release builds.
- Do not catch `Error` (or use a bare `catch (e)`) to make a failing test pass.
  Fix the cause.
- Do not use deprecated APIs. `flutter analyze` treats infos and warnings as
  fatal, and `deprecated_member_use` is an error, so any use fails CI. Migrate
  instead (`dart fix --apply` usually has a fix).

## 1a. UI library: shad

The UI is built with [`shad`](https://shad.serverpod.dev/), a Flutter port of
shadcn/ui, **instead of Material or Cupertino**.

- Import `package:flutter/widgets.dart` and `package:shad/shad.dart`. Never
  import `package:flutter/material.dart`, `package:flutter/cupertino.dart`,
  `package:material_ui/...`, `package:cupertino_ui/...` or
  `package:shad/material.dart` (the Material/Cupertino interop layer). If a
  task seems to need a Material or Cupertino widget, stop and ask.
- The app root is `ShadApp.router` (`lib/main.dart`). The themes live in
  `AppTheme` (`lib/ui/core/theme.dart`): the `nova` style and the zinc color
  scheme, light and dark, following the system setting. Read colors, text
  styles, radius and spacing from `ShadTheme.of(context)`; do not hardcode them.
  Do not create `ShadThemeData` in `build()`.
- There is no `Scaffold`, `AppBar`, `ThemeMode` or `Icons`. Use plain widgets
  and shad components; `ShadThemeMode`; `LucideIcons`.
- The `shad-overview` skill's "Basic setup" example uses `Scaffold`,
  `ThemeMode.system` and `ShadApp(home: ...)`. Do not copy those parts: the app
  already has its `ShadApp.router` root, and the rest is the rule above.
- For layout, use `ShadColumn`/`ShadRow` with `spacing`, `ShadGap` and
  `ShadPadding`. Their arguments are steps on the theme's spacing scale, not
  logical pixels.
- Use a shad component whenever one exists (button, input, dialog, sheet,
  select, toast, ...). See the `shad-overview` skill (§13) for the full list
  and each component's API.
- Code copied from Flutter docs, pub.dev or older answers almost always uses
  Material widgets. Translate it to shad when you paste.

## 2. Security

- **The app is untrusted.** Every authorization decision is made by the backend.
  The client may hide UI, but must never be the only check.
- **No secrets in the app.** No API keys, signing keys, client secrets or tokens
  in Dart code, assets, `--dart-define`, `.env` files or platform config.
  Anything shipped in the binary can be extracted. Obfuscation does not change this.
  Non-secret build settings, such as the API base URL, may use `--dart-define`.
- **Authentication** goes through the kanbot backend, never directly to the
  IdP: the app never sees IdP tokens. See `docs/oidc.md` and
  `docs/plan/auth.md` (phase 5) for the flow.
- **Tokens on the web:** the web app stores no tokens at all, in any storage.
  It is authenticated by the backend's `HttpOnly` session cookie, which Dart
  code cannot read, and sends the header `X-Kanbot-CSRF: 1` on every
  state-changing request (`POST`, `PUT`, `PATCH`, `DELETE`).
- **Tokens on native platforms:** the only token the app stores is the kanbot
  session token (`kbs_...`), and only in `TokenStore`
  (`lib/data/services/token_store.dart`), which wraps `flutter_secure_storage`
  (Keychain/Keystore) with the project's settings. Never in
  `shared_preferences`, files, or SQLite in plain text. Do not create other
  `FlutterSecureStorage` instances. Clear it on logout.
- **Never hardcode tokens**, not even placeholders like `'Bearer your_token_here'`.
  Tokens are read from the auth layer at request time.
- **HTTPS only** in anything that can ship. The one exception is local
  development against the backend on a loopback address (`localhost`,
  `127.0.0.1`, or `10.0.2.2` from the Android emulator) over `http://`. The URL
  comes from `--dart-define=API_BASE_URL=...` and is validated at startup
  by `apiBaseUrlFromEnvironment` (`lib/config/api_config.dart`), never
  hardcoded elsewhere. Release builds must pass `API_BASE_URL` explicitly and
  refuse to start with a loopback or `http://` URL.
  The only cleartext permit is the debug-only
  `android/app/src/debug/res/xml/network_security_config.xml` (loopback hosts
  only). Do not add cleartext exceptions (`usesCleartextTraffic`,
  `NSAllowsArbitraryLoads`, `network_security_config` cleartext permits) to
  release configuration.
- **No sensitive data in logs, exceptions or UI.** Do not interpolate full payloads,
  request bodies, headers, tokens, emails or other personal data into exception
  messages, logs, or `print`. For example
  `FormatException('Invalid response: $json')` is banned; use
  `FormatException('Invalid User payload: missing "email"')`.
- **Never show raw errors to users.** Do not render `snapshot.error`,
  `e.toString()` or stack traces in widgets. Map errors to user-facing messages
  and report the details to crash reporting (with personal data scrubbed).
- **Deep links and routes:**
  - Every route parameter is untrusted input. Parse and validate it
    (type, format, length) and send invalid values to an error route.
  - Protected routes must use a `GoRouter` `redirect` that checks auth state.
    Add a test proving an unauthenticated user cannot reach each protected route.
    Routes are defined in `lib/routing/router.dart` (`createRouter`, `Routes`);
    unknown paths show `NotFoundPage`.
  - **Auth callbacks:** the only custom URL scheme allowed is the login
    handoff from the kanbot backend to the app (`<app-scheme>:/auth/done`,
    where `<app-scheme>` is the app's reverse-DNS application ID). It is
    received only through `flutter_web_auth_2`, which uses
    `ASWebAuthenticationSession` on Apple platforms and Auth Tab or Custom
    Tabs on Android, and the one-time code it carries is redeemed with the
    app's PKCE verifier (S256). Windows and Linux use a loopback redirect
    (`http://127.0.0.1:<port>/auth/done`) instead. No other custom scheme,
    and no other way of receiving the callback. No App Links or Universal
    Links for login: kanbot is self-hosted, so the project controls no domain
    they could be verified for.
  - Android intent filters: `https` scheme only, always with an explicit
    `android:host`. Never a bare `<data android:scheme="https" />`. The one
    exception is `flutter_web_auth_2`'s callback activity, whose filter
    accepts only `<app-scheme>`.
  - `apple-app-site-association`: list only the paths the app handles.
    Never `"paths": ["*"]` or `{"/": "/*"}`.
- **File paths from outside the app** (downloads, deep links, server data):
  canonicalize with `p.canonicalize` and check `p.isWithin(baseDir, path)`
  before reading or writing. A string check like `!path.contains('..')` is
  not enough.
- **WebViews:** avoid. If required, disable JavaScript unless needed and restrict
  navigation to an allowlist of hosts.
- **Android:** backups stay off (`android:allowBackup="false"`,
  `fullBackupContent="false"` and `data_extraction_rules.xml` excluding
  everything); every component `exported="false"` unless it must be public (the
  launcher activity must be); use `FLAG_SECURE` on screens showing sensitive
  data.
- **Release builds** use `--obfuscate --split-debug-info=<dir>`.
- **Release web builds** go through `dart run tool/build_web.dart
  --api-base-url=https://...` only. It self-hosts CanvasKit
  (`--no-web-resources-cdn`) and injects the Content Security Policy from
  `tool/web_csp.dart` into `index.html`. Do not loosen that policy (no
  `'unsafe-eval'`, no inline scripts, no new origins) without approval. The
  web server must also send `frame-ancestors 'none'` as a header, which a
  `<meta>` policy cannot set.
- **Native downloads** (FFI hooks): verify with SHA-256, never MD5, and verify
  before the file is written to its final location (or delete it on mismatch).

## 3. Networking

- Backend calls go through the **generated** client, `KanbotApi`
  (`lib/data/api/generated/`), generated from the backend's OpenAPI document
  `../backend/openapi.json`. Repositories get it from `AppDependencies.api`
  through their constructor. Never hand-write request or response code for an
  API endpoint, never call `package:http` directly (top-level
  `http.get/post/...`, a new `http.Client`), and never edit generated files.
- After `backend/openapi.json` changes, run `dart run tool/generate_api_client.dart`
  and commit the result. It runs swagger_parser (`swagger_parser.yaml`), then
  the fixes in `tool/generated_code_fixes.dart` (for example, typing the empty
  scope lists of security requirements), `dart fix` and `dart format`, so
  generated code passes `flutter analyze` like hand-written code. When
  generated code fails analysis, add a tested fix there; never exclude it
  from analysis. CI fails if the committed client is stale. A new
  endpoint starts in the backend (`backend/AGENTS.md` §2a).
- Every generated request goes through `ApiClient`
  (`lib/data/services/api_client.dart`), an `http.BaseClient`. It adds the
  bearer token, applies the timeout, never follows redirects, and maps
  failures to the sealed `ApiException` types before generated code sees
  them. It is a transport: do not add endpoint methods to it.
- `ApiClient` refuses (with an `ArgumentError`) any request that would leave
  the API base URL: another origin, a path above the base path, or encoded
  `/` (`%2F`) and `\` (`%5C`) in a segment. The bearer token is only ever sent to the API.
- Repositories map generated models to domain models. Generated types never
  reach ViewModels or widgets.
- Long-lived services are created once in `AppDependencies.create`
  (`lib/config/dependencies.dart`), called from `main`. `createRouter` takes
  them and route builders pass what each page needs through constructors.
  Widget tests use `testDependencies()` (`test/helpers/`), whose HTTP client
  fails the test on any unexpected request.
- Every request has a timeout and is aborted when it expires
  (`http.AbortableRequest`); `ApiClient` turns that into `ApiTimeoutException`.
- Treat any `2xx` as success where the API defines it. Map failures to typed
  exceptions, not a generic `Exception('Failed')`. The backend's error
  responses are RFC 9457 problem details (`application/problem+json`) with a
  stable `code` and, for `422`, field errors. `ApiClient` turns them into
  `ApiErrorResponse` subtypes (`lib/data/services/api_exception.dart`), each
  carrying `statusCode` and `code` (`null` when the body is not a valid
  problem, for example from a proxy):
  - `400` (`ApiBadRequestException`): a client bug. Do not retry.
  - `401` (`ApiUnauthorizedException`): go to the re-auth/logout flow.
  - `403` (`ApiForbiddenException`), `404` (`ApiNotFoundException`),
    `409` (`ApiConflictException`): show a message for the `code`.
  - `422` (`ApiValidationException`): show each `fieldErrors` entry next to
    the field its JSON `pointer` names.
  - `429` (`ApiRateLimitedException`), `503` (`ApiUnavailableException`) and
    timeouts (`ApiTimeoutException`): temporary. Safe to retry with backoff.
  - `500` and other statuses (`ApiStatusException`): do not retry
    automatically.
- Switch on the exception type and `code` to choose a user-facing message.
  Never show the response body, and never show `code` itself to users.
- The web build calls the API cross-origin. Its origin must be listed in the
  backend's `CORS_ALLOWED_ORIGINS` (see `backend/AGENTS.md`). From phase 5.3
  of `docs/plan/auth.md`, the backend serves the web build and the API from one
  origin, and the web app uses a relative API base URL.

## 3a. Telemetry (OpenTelemetry)

The app reports traces and logs with OpenTelemetry (`dartastic_opentelemetry`),
over OTLP/HTTP to the API's relay at `<API_BASE_URL>/telemetry` (never to a
collector directly: the app cannot hold collector credentials, §2). Setup is in
`lib/config/telemetry.dart`, called from `main`.

- **Consent:** export starts only after the user has logged in and opted in
  (`telemetry_opt_in` from `GET /me`, set from the settings toggle through
  `PUT /me/preferences`, off by default). It stops on logout and on opt-out.
  The relay rejects everything else (`401`, or `403 telemetry_disabled`), so
  nothing can be sent before login. Until phase 5.6 of `docs/plan/auth.md`
  lands, export still starts at app launch; do not build anything new on that.

- Already instrumented: every API call (`ApiClient`: a client span, with the
  W3C `traceparent` sent so the backend's span joins the trace), uncaught
  errors (`reportUncaughtErrors`), and navigation (`reportNavigation`, route
  templates only).
- In `lib/`, get tracers and loggers from `OTelAPI.tracer(telemetryScope)` and
  `OTelAPI.logger(telemetryScope)`. They are no-ops until `initTelemetry` has
  run (tests, `OTEL_SDK_DISABLED`). Never call `OTel.tracer()`/`OTel.logger()`
  outside setup: they throw before initialization.
- Report a caught error worth investigating with `reportError(error, stack)`.
  It sends only the error's type and stack trace.
- **Never put personal data in telemetry:** no error messages, payloads,
  tokens, emails, query strings or route parameters in span names, attributes
  or log bodies. Record route templates (`/boards/:id`), never paths.
- Build settings: `--dart-define=OTEL_SERVICE_VERSION=<version>` (default
  `dev`), `--dart-define=OTEL_SDK_DISABLED=true` to turn telemetry off.
- Test instrumentation with `maybeInitializeOtelForTest()` from
  `package:dartastic_opentelemetry/testing.dart` (in-memory exporters; once
  per test file), as `test/config/telemetry_test.dart` does.

## 4. State, caching and errors

- Repositories that cache data must key the cache by its inputs (for example by
  `id`), support invalidation (a refresh must actually refetch), and clear all
  caches on logout or user switch. A single `User? _cached` that is returned for
  any `id` is a bug.
- ViewModels expose an explicit error state (for example a `Result`, or a sealed
  `Loading | Data | Error` state). `try/finally` without `catch` is not error
  handling; an exception must not escape into a button callback unhandled.
- Async work started from UI callbacks must be awaited or explicitly handled;
  no fire-and-forget futures.
- After any `await` in a widget, check `context.mounted` (or `mounted`) before
  using `context` or calling `setState`.

## 5. JSON and data parsing

- **Generated API code is exempt from this section.** Its decoders use `as`
  casts and throw a `TypeError` when a `2xx` response does not match the
  schema. Both sides of the contract are checked in CI, so such a response
  means the app and backend versions disagree: a bug to report (crash
  reporting / telemetry), not input to handle. Do not catch it. Hand-written
  parsing (problem bodies, stored data, platform channels) follows the rules
  below.
- Parse JSON with Dart 3 patterns or generated code. A failed match throws a
  `FormatException` without payload contents (see §2).
- Do not use unchecked `as` casts on decoded JSON (`json['id'] as int`). Use
  patterns or `is` checks so malformed data produces a `FormatException`, not a
  `TypeError`.
- Do not call methods on `dynamic` (for example `jsonDecode(body)['data']`).
- Malformed items in a list must fail loudly, never be silently skipped.

## 6. Performance

- Use `const` constructors wherever possible.
- No expensive work in `build()`: no parsing, sorting, filtering of large lists,
  I/O, or object creation that could be cached.
- Create `Future`s and `Stream`s in `initState` or the ViewModel, never in `build()`.
- Dispose everything you create: `TextEditingController`, `AnimationController`,
  `ScrollController`, `FocusNode`, `StreamSubscription`, `Timer`. Every `State`
  that creates one has a `dispose()` that releases it.
- Images from the network: always set `cacheWidth`/`cacheHeight` (or use a sized
  thumbnail URL), plus `errorBuilder` and a loading placeholder.
- Lists with many or unknown items use `ListView.builder` / `GridView.builder`.
- Parsing that can take over 16 ms runs in `compute()` / `Isolate.run`.
- Performance claims are measured in **profile mode on a real device**, never in
  debug mode or on an emulator.

## 7. Testing

- Every new feature has unit tests (ViewModel, Repository) **including the
  error paths**: network failure, timeout, 401, 503, malformed JSON.
- Use strict mocks: `mockito`'s `@GenerateMocks`, not `@GenerateNiceMocks`.
  Nice mocks return defaults for unstubbed calls, so tests can pass while the
  code does something unexpected. Generated `*.mocks.dart` files are
  committed: after changing a `@GenerateMocks` annotation or a mocked class,
  run `dart run build_runner build --delete-conflicting-outputs` and commit the
  result. CI fails when they are stale.
- Fake HTTP with `MockClient` from `package:http/testing.dart`, and secure
  storage with `FlutterSecureStorage.setMockInitialValues`, rather than mocking
  `http.Client` or `FlutterSecureStorage` with mockito. Test repositories
  against the real generated client and `ApiClient` over `MockClient`
  (`AppDependencies.apiFor`); do not mock `ApiClient` or generated clients.
- Always `await` async expectations: use `await expectLater(...)`, or
  `await check(...)` with `package:checks`. A bare
  `expect(future, throwsException)` without `await` is banned.
- Tests must assert behavior, not just "does not throw" or `isNotNull`.
- Key screens have golden tests (`matchesGoldenFile`). Update goldens only
  when the visual change is intended, and say so in the commit message.
- Key user flows have integration tests, including at least one
  `traceAction` performance test on the main scrolling screen.
- Coverage must not go down. CI does not enforce a threshold yet, so check
  `flutter test --coverage` yourself.

## 8. Dependencies

- Do not add a new package without explicit approval in the task (see the root
  `AGENTS.md` §2). Prefer the SDK and packages already in `pubspec.yaml`.
- Add packages with `flutter pub add`, which writes a caret constraint
  (`^x.y.z`). Never `any` (for example `intl: any` is banned).
- Never delete `pubspec.lock` wholesale. CI uses `--enforce-lockfile`.
- Do not use git or path dependencies for production code.

## 9. Localization

Localization is not set up yet. When it is:

- All user-facing strings come from ARB files. No hardcoded UI strings.
- The `flutter_gen` synthetic package has been **removed**: `synthetic-package: true`
  makes the tool exit with an error, and `package:flutter_gen/gen_l10n/...` imports
  do not exist. Do not put `synthetic-package` in `l10n.yaml` at all. Generated
  files go in the source tree (`arb-dir` / `output-dir`); import them from there.
- `l10n.yaml` sets `nullable-getter: false`, so `AppLocalizations.of(context)`
  is non-nullable and needs no `!`.
- Pass the app's own delegate and `supportedLocales` to `ShadApp.router`.
  `ShadApp` adds shad's delegate (82 locales) and the widgets delegate itself.
  No Material or Cupertino delegates (§1a).

## 10. Definition of done

Run all of these from `frontend/` before declaring a task complete. All must
pass. CI runs the same commands, after `flutter pub get --enforce-lockfile`,
and fails if `build_runner` or `tool/generate_api_client.dart` changes any
committed file.

Building for a platform needs that platform's toolchain. Linux additionally
needs `libsecret-1-dev` (and `libsecret-1-0` at runtime) and Windows the
Visual Studio C++ ATL libraries, both for `flutter_secure_storage`.

```sh
dart format --output=none --set-exit-if-changed .
dart run build_runner build --delete-conflicting-outputs   # then commit any changes
dart run tool/generate_api_client.dart                     # then commit any changes
flutter analyze   # infos and warnings are fatal by default; never pass --no-fatal-*
flutter test --coverage
dart run tool/build_web.dart --api-base-url=https://api.example.com   # release web build
```

## 11. Analyzer configuration (reference)

Do not change `analysis_options.yaml` without a maintainer's approval (§1).
Read the file itself for the full list; in summary it:

- includes `package:flutter_lints/flutter.yaml` (requires `flutter_lints: ^6.0.0`);
- excludes only generated code (`**/*.g.dart`, `**/*.freezed.dart`,
  `**/*.mocks.dart`, `lib/src/third_party/**`) and the platform folders;
- sets `strict-inference: true`;
- enables, and raises to `error`: `no_dynamic_casts`, `no_raw_types`,
  `deprecated_member_use`, `deprecated_member_use_from_same_package`,
  `unawaited_futures`, `discarded_futures`, `avoid_dynamic_calls`,
  `use_build_context_synchronously`, `cancel_subscriptions`, `close_sinks`,
  `avoid_print`, `only_throw_errors`, `avoid_catches_without_on_clauses`,
  `avoid_catching_errors`, `avoid_void_async`, `throw_in_finally`,
  `prefer_const_constructors`, `secure_pubspec_urls`;
- enables further type, error-handling and style rules (package imports,
  sorted directives, final locals, single quotes and more).

Since Dart 3.13, the `no_dynamic_casts` and `no_raw_types` lints replace the
`strict-casts` and `strict-raw-types` options (the old options still parse,
but the lints are the supported way and can be set to `error`).

## 12. Dart MCP server

The repository's `.mcp.json` configures the Dart MCP server (`dart mcp-server`,
part of the Dart SDK) with all of its tools enabled. Prefer its tools for
analysis, formatting, tests, running the app and inspecting the widget tree when
they are available to you.

## 13. Agent skills

Task-specific instructions for Dart and Flutter live in `.agents/skills/`. When a
task matches a skill's description, read its `SKILL.md` and follow it.

The skills started as copies of
[flutter/agent-plugins](https://github.com/flutter/agent-plugins) and are now
maintained in this repository, adapted to this project (shad, `ApiClient`,
`TokenStore`, `go_router`, strict mocks). Nothing updates them automatically.

- If a skill is wrong or contradicts this file, fix the skill in the same change.
- When you change a rule in this file, update every skill that shows the old
  pattern.
- Complete code examples in skills (not short fragments or deliberate "before"
  examples) must compile against the project and pass `flutter analyze`. Check
  new or changed ones by pasting them into a temporary file under `lib/` or
  `test/`, analyzing, and deleting it.

The `shad` package ships its own skill, `shad-overview`, with the API of every
component plus guides on theming, styles, layout, forms and responsive design.
Read it before building UI. It lives inside the package, so it always matches
the `shad` version in `pubspec.lock`: with the Dart MCP server, read
`package-root:shad/skills/shad-overview/SKILL.md` (and the `components/` and
`guides/` pages it links); without it, find the path to `shad` in
`.dart_tool/package_config.json`. It cannot be edited here, so §0 and §1a
override it.

## 14. Hot reload while developing

This applies only when the Dart MCP server is available to you and a Flutter app
from this project is already running. If either is missing, skip this section.
Do not start an app or install tools just to hot reload.

After you change a `.dart` file under `lib/`:

1. **Skip** if the change is outside `lib/` (for example `test/`, `integration_test/`,
   `benchmark/`, `test_driver/`, `example/`), or only touches comments, doc comments
   or whitespace.
2. **Find the running app** with the Dart MCP server's running-app tools (`dtd`,
   `list_running_apps` or `vm_service`).
3. **Reload:**
   - Use `hot_reload` after changing widgets (including `build` methods) or
     ordinary method bodies.
   - Use `hot_restart` after changing `main()`, state initialization (such as
     `initState`), global or static state, or other fundamental app logic.

Hot reload is for seeing a change quickly. It does not replace the checks in §10:
a change that reloads fine can still fail analysis or tests.

Adapted from [flutter/agent-plugins `rules/flutter-hot-reload.md`](https://github.com/flutter/agent-plugins/blob/main/rules/flutter-hot-reload.md).
