---
name: dart-generate-test-mocks
description: Define and generate strict mock objects with `package:mockito` and `build_runner`, and fake HTTP with `MockClient`. Use when unit testing classes that depend on repositories, services or the backend.
---
# Testing with Mocks

## Contents
- [Structuring Code for Testability](#structuring-code-for-testability)
- [Choosing a Test Double](#choosing-a-test-double)
- [Generating Mocks](#generating-mocks)
- [Implementing Unit Tests](#implementing-unit-tests)
- [Workflow: Creating and Running Mocked Tests](#workflow-creating-and-running-mocked-tests)
- [Examples](#examples)

## Structuring Code for Testability
- Inject every dependency through the constructor (`ApiConnection`, `TokenStore`, repositories, `http.Client`). Never create them inside the class under test.
- Represent URLs as `Uri` objects.

`mockito`, `build_runner` and `http` (with `package:http/testing.dart`) are already dependencies. Do not add others for testing without approval.

## Choosing a Test Double
- **HTTP / the backend:** fake it with `MockClient` from `package:http/testing.dart`, as the `http.Client` of a real `ApiConnection` (which builds the real `ApiClient` and generated client), then `connect` it to a base URL. Do not mock `http.Client`, `ApiClient` or the generated clients with mockito: the real ones test the request, decoding and error mapping.
- **Secure storage:** use `FlutterSecureStorage.setMockInitialValues`, or mock `TokenStore`. Never mock `FlutterSecureStorage` with mockito.
- **Your own classes** (`TokenStore`, repositories, in tests of the layer above them): mockito.
- Never mock the class under test.

## Generating Mocks
- Use **`@GenerateMocks([Type])`**, never `@GenerateNiceMocks`. Strict mocks throw on unstubbed calls, so a test cannot pass while the code does something unexpected.
- Put the annotation on `main()` in the test file, and import the generated `<name>_test.mocks.dart`.
- Generate with:
  ```bash
  dart run build_runner build --delete-conflicting-outputs
  ```
- **Commit the generated `*.mocks.dart` files.** CI regenerates them and fails if they differ. Never edit them by hand.

## Implementing Unit Tests
- **Stubbing:** stub every call the code under test makes, before calling it.
  - `when(mock.method()).thenReturn(value)` for synchronous methods.
  - `thenAnswer((_) async => value)` for `Future`/`Stream`. Never `thenReturn` with a future.
  - `thenThrow(const ApiTimeoutException())` for error paths.
- **Verification:** `verify(mock.method()).called(1)`, `verifyNever(...)`. Use matchers (`any`, `anyNamed`, `captureAny`) only where the exact argument does not matter.
- **Async expectations are awaited:** `await expectLater(future, throwsA(isA<ApiTimeoutException>()))`. A bare `expect(future, throwsException)` is banned: the test can finish before the future completes.
- **Assert the result,** not just that nothing threw. Cover the error paths: network failure, timeout, 401, 503, malformed JSON.

## Workflow: Creating and Running Mocked Tests

### Task Progress
- [ ] 1. Identify the dependencies to replace (see Choosing a Test Double).
- [ ] 2. Make sure they are injected through the constructor.
- [ ] 3. In the test file, add `@GenerateMocks([Dependency])` on `main()` and import `<name>_test.mocks.dart`.
- [ ] 4. Run `dart run build_runner build --delete-conflicting-outputs`.
- [ ] 5. Write the tests: stub, act, assert, verify.
- [ ] 6. Run `flutter test`.
- [ ] 7. Commit the `.mocks.dart` file together with the test.

### Feedback Loop: Test Failures
1. Run `flutter test` (or `build_runner` if generation failed).
2. Read the error:
   - `MissingStubError`: the code made a call you did not stub. Stub it if it is expected; otherwise the code is wrong. Do not switch to nice mocks.
   - `ArgumentError` from an async stub: change `thenReturn` to `thenAnswer`.
   - `build_runner` fails: check that the `.mocks.dart` import matches the test file name.
3. Fix and repeat until all tests pass.

## Examples

### Repository Test over a Faked Backend

**System Under Test (`lib/data/repositories/server_status_repository.dart`)**
```dart
import 'package:kanbot/data/services/api_connection.dart';
import 'package:kanbot/data/services/api_exception.dart';

class ServerStatusRepository {
  ServerStatusRepository({required this._connection});

  final ApiConnection _connection;

  /// `false` while the backend is not ready (`503`). Throws any other
  /// `ApiException`.
  Future<bool> isReady() async {
    try {
      await _connection.api.health.ready();
      return true;
    } on ApiUnavailableException {
      return false;
    }
  }
}
```

**Test (`test/data/repositories/server_status_repository_test.dart`)**
```dart
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:kanbot/data/repositories/server_status_repository.dart';
import 'package:kanbot/data/services/api_connection.dart';
import 'package:kanbot/data/services/api_exception.dart';
import 'package:kanbot/data/services/token_store.dart';

void main() {
  // Signed out: TokenStore reads the in-memory fake storage.
  setUp(() => FlutterSecureStorage.setMockInitialValues({}));

  ServerStatusRepository repository(MockClient backend) =>
      ServerStatusRepository(
        connection: ApiConnection(
          newHttpClient: () => backend,
          tokenStore: TokenStore(),
        )..connect(Uri.parse('https://api.example.com/')),
      );

  test('is ready on 200', () async {
    final backend = MockClient((request) async {
      expect(request.url.path, '/ready');
      return http.Response('', 200);
    });

    expect(await repository(backend).isReady(), isTrue);
  });

  test('is not ready on 503', () async {
    final backend = MockClient((_) async => http.Response('', 503));

    expect(await repository(backend).isReady(), isFalse);
  });

  test('passes other failures through', () async {
    final backend = MockClient(
      (_) async => throw http.ClientException('connection refused'),
    );

    await expectLater(
      repository(backend).isReady(),
      throwsA(isA<ApiNetworkException>()),
    );
  });
}
```

### Mocking a Repository

In tests of a ViewModel, mock the repository with mockito:

```dart
@GenerateMocks([ServerStatusRepository])
void main() {
  test('shows maintenance while the server is not ready', () async {
    final repository = MockServerStatusRepository();
    when(repository.isReady()).thenAnswer((_) async => false);
    // ... build the ViewModel with `repository`, then assert on its state.
  });
}
```
