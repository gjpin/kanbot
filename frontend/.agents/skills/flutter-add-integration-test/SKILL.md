---
name: flutter-add-integration-test
description: Configures Flutter Driver for app interaction and converts MCP actions into permanent integration tests. Use when adding integration testing to a project, exploring UI components via MCP, or automating user flows with the integration_test package.
---
# Implementing Flutter Integration Tests

## Contents
- [Project Setup and Dependencies](#project-setup-and-dependencies)
- [Interactive Exploration via MCP](#interactive-exploration-via-mcp)
- [Test Authoring Guidelines](#test-authoring-guidelines)
- [Execution and Profiling](#execution-and-profiling)
- [Workflow: End-to-End Integration Testing](#workflow-end-to-end-integration-testing)
- [Examples](#examples)

## Project Setup and Dependencies

Configure the project to support integration testing and Flutter Driver extensions.

1. Add the development dependency (needs approval in the task, `frontend/AGENTS.md` §8; `flutter_test` is already there):
   ```bash
   flutter pub add 'dev:integration_test:{"sdk":"flutter"}'
   ```
2. Enable the Flutter Driver extension in a dedicated `lib/main_test.dart`, never in `lib/main.dart`, so it is never part of a release build:
   - Import `package:flutter_driver/driver_extension.dart`.
   - Call `enableFlutterDriverExtension();` before `runApp()`.
3. Add `Key` parameters (e.g., `ValueKey('login_button')`) to critical widgets in the application code to ensure reliable targeting during tests.

## Interactive Exploration via MCP

Use the Dart/Flutter MCP server tools to interactively explore and manipulate the application state before writing static tests.

- **Launch**: Execute `launch_app` with `target: "lib/main_test.dart"` to start the application and acquire the DTD URI.
- **Inspect**: Execute `get_widget_tree` to discover available `Key`s, `Text` nodes, and widget `Type`s.
- **Interact**: Execute `tap`, `enter_text`, and `scroll` to simulate user flows.
- **Wait**: Always execute `waitFor` or verify state with `get_health` when navigating or triggering animations.
- **Troubleshoot Unmounted Widgets**: If a widget is not found in the tree, it may be lazily loaded in a `SliverList` or `ListView`. Execute `scroll` or `scrollIntoView` to force the widget to mount before interacting with it.

## Test Authoring Guidelines

Structure integration tests using the `flutter_test` API paradigm. 

- Create a dedicated `integration_test/` directory at the project root.
- Name all test files using the `<name>_test.dart` convention.
- Initialize the binding by calling `IntegrationTestWidgetsFlutterBinding.ensureInitialized();` at the start of `main()`.
- Load the application UI using `await tester.pumpWidget(KanbotApp(router: createRouter()));`.
- Trigger frames and wait for animations to complete using `await tester.pumpAndSettle();` after interactions like `tester.tap()`.
- Assert widget visibility using `expect(find.byKey(ValueKey('foo')), findsOneWidget);` or `findsNothing`.
- Scroll to specific off-screen widgets using `await tester.scrollUntilVisible(itemFinder, 500.0, scrollable: listFinder);`.

**Conditional Logic for Legacy `flutter_driver`:**
- If maintaining or migrating legacy `flutter_driver` tests, use `driver.waitFor()`, `driver.waitForAbsent()`, `driver.tap()`, and `driver.scroll()` instead of the `WidgetTester` APIs.

## Execution and Profiling

Execute tests using the `flutter drive` command. Require a host driver script located in `test_driver/integration_test.dart` that calls `integrationDriver()`.

**Conditional Execution Targets:**
- **If testing on Chrome:** Launch `chromedriver --port=4444` in a separate terminal, then run:
  `flutter drive --driver=test_driver/integration_test.dart --target=integration_test/app_test.dart -d chrome`
- **If testing headless web:** Run with `-d web-server`.
- **If testing on Android (Local):** Run `flutter drive --driver=test_driver/integration_test.dart --target=integration_test/app_test.dart`.
- **If testing on Firebase Test Lab (Android):** 
  1. Build debug APK: `flutter build apk --debug`
  2. Build test APK: `./gradlew app:assembleAndroidTest`
  3. Upload both APKs to the Firebase Test Lab console.

## Workflow: End-to-End Integration Testing

Copy and follow this checklist to implement and verify integration tests.

- [ ] **Task Progress: Setup**
  - [ ] Add `integration_test` to `pubspec.yaml`.
  - [ ] Inject `enableFlutterDriverExtension()` into the app entry point.
  - [ ] Assign `ValueKey`s to target widgets.
- [ ] **Task Progress: Exploration**
  - [ ] Run `launch_app` via MCP.
  - [ ] Map the widget tree using `get_widget_tree`.
  - [ ] Validate interaction paths using MCP tools (`tap`, `enter_text`).
- [ ] **Task Progress: Authoring**
  - [ ] Create `integration_test/app_test.dart`.
  - [ ] Write test cases using `WidgetTester` APIs.
  - [ ] Create `test_driver/integration_test.dart` with `integrationDriver()`.
- [ ] **Task Progress: Execution & Feedback Loop**
  - [ ] Run `flutter drive --driver=test_driver/integration_test.dart --target=integration_test/app_test.dart`.
  - [ ] **Feedback Loop**: Review test output -> If `PumpAndSettleTimedOutException` occurs, check for infinite animations -> If widget not found, add `scrollUntilVisible` -> Re-run test until passing.

## Examples

### Standard Integration Test (`integration_test/app_test.dart`)

```dart
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:kanbot/main.dart';
import 'package:kanbot/routing/router.dart';
import 'package:shad/shad.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  group('end-to-end', () {
    testWidgets('tapping the button increments the counter', (tester) async {
      await tester.pumpWidget(KanbotApp(router: createRouter()));

      expect(find.text('0'), findsOneWidget);

      await tester.tap(find.byIcon(LucideIcons.plus));
      await tester.pumpAndSettle();

      expect(find.text('1'), findsOneWidget);
    });
  });
}
```

### Scrolling Performance Test (`integration_test/scrolling_test.dart`)

The main scrolling screen needs one of these (`frontend/AGENTS.md` §7). Run it in profile mode on a real device.

```dart
import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:kanbot/main.dart';
import 'package:kanbot/routing/router.dart';

void main() {
  final binding = IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('scrolls the board smoothly', (tester) async {
    await tester.pumpWidget(KanbotApp(router: createRouter()));

    final list = find.byType(Scrollable).first;
    await binding.traceAction(() async {
      await tester.fling(list, const Offset(0, -500), 1000);
      await tester.pumpAndSettle();
    }, reportKey: 'scrolling_timeline');
  });
}
```

### Host Driver Script (`test_driver/integration_test.dart`)

```dart
import 'package:integration_test/integration_test_driver.dart';

Future<void> main() => integrationDriver();
```

### Performance Profiling Driver Script (`test_driver/perf_driver.dart`)

Use this driver script if you wrap your test actions in `binding.traceAction()` to capture performance metrics.

```dart
import 'package:flutter_driver/flutter_driver.dart' as driver;
import 'package:integration_test/integration_test_driver.dart';

Future<void> main() {
  return integrationDriver(
    responseDataCallback: (data) async {
      if (data case {'scrolling_timeline': final Map<String, Object?> json}) {
        final timeline = driver.Timeline.fromJson(json);

        final summary = driver.TimelineSummary.summarize(timeline);

        await summary.writeTimelineToFile(
          'scrolling_timeline',
          pretty: true,
          includeSummary: true,
        );
      }
    },
  );
}
```
