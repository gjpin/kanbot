---
name: flutter-add-widget-test
description: Implement a component-level test using `WidgetTester` to verify UI rendering and user interactions (tapping, scrolling, entering text). Use when validating that a specific widget displays correct data and responds to events as expected.
---
# Writing Flutter Widget Tests

## Contents
- [Setup & Configuration](#setup--configuration)
- [Core Components](#core-components)
- [Workflow: Implementing a Widget Test](#workflow-implementing-a-widget-test)
- [Interaction & State Management](#interaction--state-management)
- [Examples](#examples)

## Setup & Configuration

Ensure the testing environment is properly configured before authoring widget tests.

1. `flutter_test` is already in `dev_dependencies`.
2. Place test files under `test/`, mirroring the `lib/` path (`lib/ui/features/todo/views/todo_list.dart` → `test/ui/features/todo/views/todo_list_test.dart`).
3. Suffix all test file names with `_test.dart`.
4. shad widgets need a `ShadTheme` above them. Pump screens inside the real app shell, `KanbotApp` with a `GoRouter`, as in the example. Do not build a `MaterialApp`, and do not use `ShadApp(home: ...)`.

## Core Components

Utilize the following `flutter_test` components to interact with and validate the widget tree:

*   **`WidgetTester`**: The primary interface for building and interacting with widgets in the test environment. Provided automatically by the `testWidgets()` function.
*   **`Finder`**: Locates widgets in the test environment (e.g., `find.text('Submit')`, `find.byType(ShadInput)`, `find.byIcon(LucideIcons.plus)`, `find.byKey(Key('submit_btn'))`).
*   **`Matcher`**: Verifies the presence or state of widgets located by a `Finder` (e.g., `findsOneWidget`, `findsNothing`, `findsNWidgets(2)`, `matchesGoldenFile`).

## Workflow: Implementing a Widget Test

Copy the following checklist to track progress when implementing a new widget test.

### Task Progress
- [ ] **Step 1: Define the test.** Use `testWidgets('description', (WidgetTester tester) async { ... })`.
- [ ] **Step 2: Build the widget.** Render the UI inside `KanbotApp` (see Setup step 4 and the example).
- [ ] **Step 3: Locate elements.** Instantiate `Finder` objects for the target widgets.
- [ ] **Step 4: Verify initial state.** Use `expect(finder, matcher)` to validate the initial render.
- [ ] **Step 5: Simulate interactions.** Execute gestures or inputs (e.g., `await tester.tap(buttonFinder)`).
- [ ] **Step 6: Rebuild the tree.** Call `await tester.pump()` or `await tester.pumpAndSettle()` to process state changes.
- [ ] **Step 7: Verify updated state.** Use `expect()` to validate the UI after the interaction.
- [ ] **Step 8: Run and validate.** Execute `flutter test test/your_test_file_test.dart`.
- [ ] **Step 9: Feedback Loop.** Review test output -> identify failing matchers -> adjust widget logic or test assertions -> re-run until passing.

## Interaction & State Management

Apply the following conditional logic based on the type of interaction or state change being tested:

*   **If testing static rendering:** Call `await tester.pumpWidget()` once, then immediately run `expect()` assertions.
*   **If testing standard state changes (e.g., button taps):** 
    1. Call `await tester.tap(finder)`.
    2. Call `await tester.pump()` to trigger a single frame rebuild.
*   **If testing animations, transitions, or asynchronous UI updates:** 
    1. Trigger the action (e.g., `await tester.drag(finder, Offset(500, 0))`).
    2. Call `await tester.pumpAndSettle()` to repeatedly pump frames until no more frames are scheduled (animation completes).
*   **If testing text input:** Call `await tester.enterText(find.byType(ShadInput), 'Input string')`.
*   **If testing items in a dynamic or long list:** Call `await tester.scrollUntilVisible(itemFinder, 500.0, scrollable: listFinder)` to ensure the target widget is rendered before interacting with it.

## Examples

### High-Fidelity Widget Test Implementation

**Target Widget (`lib/ui/features/todo/views/todo_list.dart`):**
```dart
import 'package:flutter/widgets.dart';
import 'package:shad/shad.dart';

class TodoList extends StatefulWidget {
  const TodoList({super.key});

  @override
  State<TodoList> createState() => _TodoListState();
}

class _TodoListState extends State<TodoList> {
  final _todos = <String>[];
  final _controller = TextEditingController();

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _add() => setState(() {
    _todos.add(_controller.text);
    _controller.clear();
  });

  @override
  Widget build(BuildContext context) {
    return ShadColumn(
      spacing: 2,
      children: [
        ShadRow(
          spacing: 2,
          children: [
            Expanded(child: ShadInput(controller: _controller)),
            ShadButton(onPressed: _add, child: const Icon(LucideIcons.plus)),
          ],
        ),
        Expanded(
          child: ListView.builder(
            itemCount: _todos.length,
            itemBuilder: (context, index) {
              final todo = _todos[index];
              return Dismissible(
                key: ValueKey('$todo$index'),
                onDismissed: (_) => setState(() => _todos.removeAt(index)),
                child: ShadPadding.all(2, child: Text(todo)),
              );
            },
          ),
        ),
      ],
    );
  }
}
```

**Test Implementation (`test/ui/features/todo/views/todo_list_test.dart`):**
```dart
import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:kanbot/main.dart';
import 'package:kanbot/ui/features/todo/views/todo_list.dart';
import 'package:shad/shad.dart';

/// Pumps [screen] inside the real app shell (ShadApp.router and AppTheme).
Future<void> pumpScreen(WidgetTester tester, Widget screen) =>
    tester.pumpWidget(
      KanbotApp(
        router: GoRouter(
          routes: [GoRoute(path: '/', builder: (context, state) => screen)],
        ),
      ),
    );

void main() {
  testWidgets('adds and removes a todo item', (tester) async {
    await pumpScreen(tester, const TodoList());

    expect(find.byType(Dismissible), findsNothing);

    await tester.enterText(find.byType(ShadInput), 'Buy groceries');
    await tester.tap(find.byIcon(LucideIcons.plus));
    await tester.pump();

    expect(find.text('Buy groceries'), findsOneWidget);

    // Swipe the item away and wait for the dismiss animation to finish.
    await tester.drag(find.byType(Dismissible), const Offset(500, 0));
    await tester.pumpAndSettle();

    expect(find.text('Buy groceries'), findsNothing);
  });
}
```
