---
name: flutter-setup-declarative-routing
description: Add routes, route parameters, auth guards, nested navigation and platform deep links with `go_router` and `ShadApp.router`. Use when adding a screen, a deep link, or a protected route.
---
# Routing and Deep Linking

## Contents
- [Core Concepts](#core-concepts)
- [Workflow: Adding a Route](#workflow-adding-a-route)
- [Workflow: Protecting Routes](#workflow-protecting-routes)
- [Workflow: Configuring Platform Deep Linking](#workflow-configuring-platform-deep-linking)
- [Workflow: Implementing Nested Navigation](#workflow-implementing-nested-navigation)
- [Examples](#examples)

## Core Concepts

The app already uses `go_router`:

- `lib/routing/router.dart` holds `createRouter()` (the `GoRouter`) and `Routes` (path constants). Add every route there. Never use path string literals elsewhere.
- `createRouter()` takes `AppDependencies` (`lib/config/dependencies.dart`). Route builders pass the services a page needs to it (or its ViewModel) through constructors. Tests pass `testDependencies()` (`test/helpers/test_dependencies.dart`).
- `lib/main.dart` builds the router once and passes it to `KanbotApp`, which binds it to `ShadApp.router`. Never create a `GoRouter` in `build()`.
- Unknown paths, including deep links, show `NotFoundPage` (`errorBuilder`).
- **ShellRoute / StatefulShellRoute** wrap child routes in a persistent UI shell (e.g. a tab bar). `StatefulShellRoute` keeps the state of each branch.
- **Path URL strategy** (`usePathUrlStrategy()` from `package:flutter_web_plugins/url_strategy.dart`, called in `main()` before `runApp`) removes the `#` from web URLs. The app does not use it yet. Adding it needs the web host to serve `index.html` for every path.

## Workflow: Adding a Route

### Task Progress
- [ ] Add the path to `Routes`.
- [ ] Add the `GoRoute` in `createRouter()`.
- [ ] Parse and validate every path and query parameter. Invalid values go to `NotFoundPage`, never `!`.
- [ ] If the route needs a signed-in user, protect it (next workflow).
- [ ] Test it in `test/routing/router_test.dart`: valid location, invalid parameter, and (if protected) unauthenticated access.

Route parameters are untrusted input: a deep link can put anything in them. Check type, format and length.

```dart
abstract final class Routes {
  static const String home = '/';
  static const String board = '/boards/:id';

  static String boardPath(int id) => '/boards/$id';
}

/// A positive integer id, or null.
int? parseId(String? raw) => switch (int.tryParse(raw ?? '')) {
  final id? when id > 0 => id,
  _ => null,
};

// In createRouter():
GoRoute(
  path: Routes.board,
  builder: (context, state) => switch (parseId(state.pathParameters['id'])) {
    final id? => BoardPage(id: id),
    null => const NotFoundPage(),
  },
),
```

## Workflow: Protecting Routes

Every protected route goes through a `redirect` that checks auth state. The backend still authorizes every request; the redirect only keeps the UI consistent.

### Task Progress
- [ ] Inject the auth state (a `Listenable`) into `createRouter()`.
- [ ] Add a top-level `redirect` and pass the auth state as `refreshListenable`, so logging out leaves protected screens immediately.
- [ ] Send signed-in users away from the login page.
- [ ] Test, for **each** protected route, that an unauthenticated user ends up on the login page.

```dart
GoRouter createRouter({
  required AppDependencies dependencies,
  required AuthState auth,
  String initialLocation = Routes.home,
}) => GoRouter(
  initialLocation: initialLocation,
  refreshListenable: auth,
  redirect: (context, state) {
    final onLogin = state.matchedLocation == Routes.login;
    return switch ((auth.isSignedIn, onLogin)) {
      (false, false) => Routes.login,
      (true, true) => Routes.home,
      _ => null,
    };
  },
  routes: [/* ... */],
  errorBuilder: (context, state) => const NotFoundPage(),
);
```

```dart
testWidgets('signed-out user cannot open a board', (tester) async {
  final router = createRouter(
    dependencies: testDependencies(),
    auth: FakeAuthState(signedIn: false),
    initialLocation: Routes.boardPath(1),
  );
  await tester.pumpWidget(KanbotApp(router: router));
  await tester.pumpAndSettle();

  expect(find.byType(LoginPage), findsOneWidget);
  expect(find.byType(BoardPage), findsNothing);
});
```

## Workflow: Configuring Platform Deep Linking

Use only verified App Links (Android) and Universal Links (iOS) for deep links. They are not used for login: the login handoff from the kanbot backend is the one allowed custom URL scheme, received only through `flutter_web_auth_2` (`frontend/AGENTS.md` §2, "Auth callbacks"). Do not add any other custom scheme. Editing `android/` and `ios/` needs the task to ask for it (`frontend/AGENTS.md` §1).

### Task Progress
- [ ] Determine target platforms.
- [ ] Android: intent filter + `assetlinks.json`.
- [ ] iOS: `Info.plist` + entitlements + `apple-app-site-association`.
- [ ] Validate on a device or emulator.

### Android
1. **`AndroidManifest.xml`**: add the intent filter inside the `.MainActivity` `<activity>`. `https` only, always with an explicit `android:host`. Never `http`, never a `<data>` without a host. Keep every other component `exported="false"`.
```xml
<intent-filter android:autoVerify="true">
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="https" android:host="yourdomain.com" android:pathPrefix="/boards/" />
</intent-filter>
```
2. **`assetlinks.json`** at `https://yourdomain.com/.well-known/assetlinks.json`:
```json
[{
  "relation": ["delegate_permission/common.handle_all_urls"],
  "target": {
    "namespace": "android_app",
    "package_name": "com.yourcompany.yourapp",
    "sha256_cert_fingerprints": ["YOUR_SHA256_FINGERPRINT"]
  }
}]
```

### iOS
1. **`Info.plist`**: opt in to Flutter's deep link handler. (Set it to `NO` if a plugin such as `app_links` handles links.)
```xml
<key>FlutterDeepLinkingEnabled</key>
<true/>
```
2. **`Runner.entitlements`**:
```xml
<key>com.apple.developer.associated-domains</key>
<array>
  <string>applinks:yourdomain.com</string>
</array>
```
3. **`apple-app-site-association`** (no `.json` extension) at `https://yourdomain.com/.well-known/apple-app-site-association`. List only the paths the app handles. Never `"paths": ["*"]` or `{"/": "/*"}`.
```json
{
  "applinks": {
    "details": [{
      "appIDs": ["TEAM_ID.com.yourcompany.yourapp"],
      "components": [{"/": "/boards/*"}]
    }]
  }
}
```

### Validation
- **Android:**
  ```bash
  adb shell 'am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d "https://yourdomain.com/boards/123"' com.yourcompany.yourapp
  ```
- **iOS** (booted simulator):
  ```bash
  xcrun simctl openurl booted https://yourdomain.com/boards/123
  ```
- Also open an invalid link (`/boards/abc`) and confirm it shows `NotFoundPage`.

## Workflow: Implementing Nested Navigation

Use `StatefulShellRoute` for a persistent shell (tab bar, sidebar) that keeps each branch's state.

### Task Progress
- [ ] Define `StatefulShellRoute.indexedStack` in `createRouter()`.
- [ ] Create one `StatefulShellBranch` per tab.
- [ ] Build the shell widget from shad components (below), or `ShadSidebarScaffold` for a sidebar layout (see the `shad-overview` skill).

```dart
StatefulShellRoute.indexedStack(
  builder: (context, state, navigationShell) =>
      TabShell(navigationShell: navigationShell),
  branches: [
    StatefulShellBranch(
      routes: [GoRoute(path: Routes.home, builder: (context, state) => const HomePage())],
    ),
    StatefulShellBranch(
      routes: [GoRoute(path: Routes.settings, builder: (context, state) => const SettingsPage())],
    ),
  ],
),
```

## Examples

### Shell Widget
```dart
import 'package:flutter/widgets.dart';
import 'package:go_router/go_router.dart';
import 'package:shad/shad.dart';

class TabShell extends StatelessWidget {
  const TabShell({super.key, required this.navigationShell});

  final StatefulNavigationShell navigationShell;

  void _goBranch(int index) => navigationShell.goBranch(
    index,
    // Tapping the active tab returns to its initial location.
    initialLocation: index == navigationShell.currentIndex,
  );

  @override
  Widget build(BuildContext context) {
    return ShadColumn(
      children: [
        Expanded(child: navigationShell),
        const ShadSeparator.horizontal(),
        ShadRow(
          mainAxisAlignment: .spaceEvenly,
          children: [
            _TabButton(
              icon: LucideIcons.house,
              label: 'Home',
              selected: navigationShell.currentIndex == 0,
              onPressed: () => _goBranch(0),
            ),
            _TabButton(
              icon: LucideIcons.settings,
              label: 'Settings',
              selected: navigationShell.currentIndex == 1,
              onPressed: () => _goBranch(1),
            ),
          ],
        ),
      ],
    );
  }
}

class _TabButton extends StatelessWidget {
  const _TabButton({
    required this.icon,
    required this.label,
    required this.selected,
    required this.onPressed,
  });

  final IconData icon;
  final String label;
  final bool selected;
  final VoidCallback onPressed;

  @override
  Widget build(BuildContext context) => selected
      ? ShadButton.secondary(onPressed: onPressed, leading: Icon(icon), child: Text(label))
      : ShadButton.ghost(onPressed: onPressed, leading: Icon(icon), child: Text(label));
}
```

### Programmatic Navigation
Use the `go_router` extension methods with `Routes`, never string literals.

```dart
// Replaces the current stack with the target location.
context.go(Routes.boardPath(123));

// Pushes the target onto the existing stack.
context.push(Routes.boardPath(123));

// Pops the current route.
context.pop();
```
