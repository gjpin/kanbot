---
name: dart-add-unit-test
description: Write and organize unit tests for functions, methods, and classes using `flutter_test`. Use when creating new logic or fixing bugs to ensure code remains correct and regression-free.
---
# Testing Dart and Flutter Applications

## Contents
- [Structuring Test Files](#structuring-test-files)
- [Writing Tests](#writing-tests)
- [Executing Tests](#executing-tests)
- [Test Implementation Workflow](#test-implementation-workflow)
- [Examples](#examples)

## Structuring Test Files
Organize test files to mirror the `lib` directory structure to maintain predictability.

* Place all test code within the `test` directory at the root of the package.
* Append `_test.dart` to the end of all test file names (e.g., `lib/src/utils.dart` should be tested in `test/src/utils_test.dart`).
* If writing integration tests, place them in an `integration_test` directory at the root of the package.

## Writing Tests
This is a Flutter project: use `flutter_test`, which re-exports `package:test`'s API. `package:test` is not a dependency.

* Import `package:flutter_test/flutter_test.dart`.
* Group related tests using the `group()` function to provide shared context.
* Define individual test cases using the `test()` function.
* Validate outcomes using the `expect()` function alongside matchers (e.g., `equals()`, `isTrue`, `throwsA()`).
* Write asynchronous tests using standard `async`/`await` syntax. The test runner automatically waits for the `Future` to complete.
* Always `await` async expectations: `await expectLater(future, throwsA(...))`. A bare `expect(future, throwsException)` without `await` is banned.
* Assert the actual result. A test that only checks "does not throw" or `isNotNull` tests nothing. Cover error paths (network failure, timeout, 401, 503, malformed JSON).
* Manage test setup and teardown using `setUp()` and `tearDown()` callbacks.
* If testing code that relies on dependency injection, use `package:mockito` with `@GenerateMocks` (never `@GenerateNiceMocks`); see the `dart-generate-test-mocks` skill.

## Executing Tests
Select the appropriate test runner based on the project type and test location.

* Run tests from `frontend/` with `flutter test` (all) or `flutter test test/path/to/file_test.dart` (one file).
* Integration tests are not run by default: `flutter test integration_test`.

## Test Implementation Workflow

Follow this sequential workflow when implementing new test suites. Copy the checklist to track your progress.

### Task Progress
- [ ] 1. Create the test file in the `test/` directory, ensuring the `_test.dart` suffix.
- [ ] 2. Import `package:flutter_test/flutter_test.dart` and the target library.
- [ ] 3. Define a `main()` function.
- [ ] 4. Initialize shared resources or mocks using `setUp()`.
- [ ] 5. Write `test()` cases grouped by functionality using `group()`.
- [ ] 6. Execute the test suite using the appropriate CLI command.
- [ ] 7. **Feedback Loop**: Run test -> Review stack trace for failures -> Fix implementation or assertions -> Re-run until passing.

## Examples

### Standard Unit Test Suite
Demonstrates grouping, setup, synchronous, and asynchronous testing.

```dart
import 'package:flutter_test/flutter_test.dart';
import 'package:kanbot/calculator.dart';

void main() {
  group('Calculator', () {
    late Calculator calc;

    setUp(() {
      calc = Calculator();
    });

    test('adds two numbers correctly', () {
      expect(calc.add(2, 3), equals(5));
    });

    test('handles asynchronous operations', () async {
      final result = await calc.fetchRemoteValue();
      expect(result, greaterThan(0));
    });
  });
}
```

### Mocking with Mockito
Strict mocks via `@GenerateMocks`. Generate with `dart run build_runner build --delete-conflicting-outputs` and commit the `.mocks.dart` file.

```dart
import 'package:flutter_test/flutter_test.dart';
import 'package:kanbot/data/repositories/server_status_repository.dart';
import 'package:kanbot/data/services/api_exception.dart';
import 'package:kanbot/ui/features/status/view_models/status_view_model.dart';
import 'package:mockito/annotations.dart';
import 'package:mockito/mockito.dart';

import 'status_view_model_test.mocks.dart';

// Mock the layer below the class under test. Repositories themselves are
// tested against the real generated API client over `MockClient` (see the
// `dart-generate-test-mocks` skill), never with a mocked `ApiClient`.
@GenerateMocks([ServerStatusRepository])
void main() {
  group('StatusViewModel', () {
    late MockServerStatusRepository repository;
    late StatusViewModel viewModel;

    setUp(() {
      repository = MockServerStatusRepository();
      viewModel = StatusViewModel(repository: repository);
    });

    test('reports a ready server', () async {
      when(repository.isReady()).thenAnswer((_) async => true);

      await viewModel.load();

      expect(viewModel.state, isA<StatusReady>());
      verify(repository.isReady()).called(1);
    });

    test('shows an error when the network fails', () async {
      when(
        repository.isReady(),
      ).thenAnswer((_) async => throw const ApiNetworkException());

      await viewModel.load();

      expect(viewModel.state, isA<StatusError>());
    });
  });
}
```
