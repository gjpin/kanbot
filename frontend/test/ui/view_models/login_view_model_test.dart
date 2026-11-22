import 'package:flutter_test/flutter_test.dart';
import 'package:kanbot/config/dependencies.dart';
import 'package:kanbot/data/repositories/auth_repository.dart';
import 'package:kanbot/data/services/api_exception.dart';
import 'package:kanbot/ui/features/auth/login_view_model.dart';

import '../../helpers/fake_backend.dart';
import '../../helpers/test_dependencies.dart';

LoginViewModel _viewModel(AppDependencies dependencies, {String? error}) =>
    LoginViewModel(
      auth: dependencies.auth,
      connection: dependencies.connection,
      serverStore: dependencies.serverStore,
      error: error,
    );

/// A sign-in that fails in a way the `WebAuth` contract does not list.
final class _Unexpected implements Exception {
  const _Unexpected();
}

void main() {
  test('an unexpected sign-in failure is shown, not thrown', () async {
    final backend = FakeBackend()..on('GET', '/auth/config', authConfig());
    final viewModel = _viewModel(
      testDependencies(
        backend: backend,
        webAuth: FakeWebAuth((_) => throw const _Unexpected()),
      ),
    );

    await viewModel.signIn();

    expect(viewModel.error, isA<_Unexpected>());
    expect(viewModel.busy, isFalse);
  });

  test('a retry that meets a contract break says so', () async {
    final backend = FakeBackend()
      ..on('GET', '/auth/config', problem(503, 'unavailable'), status: 503);
    final dependencies = testDependencies(backend: backend);
    await dependencies.auth.refresh();
    final viewModel = _viewModel(dependencies);
    expect(viewModel.error, isA<ApiUnavailableException>());

    backend.on('GET', '/auth/config', {'hello': 'world'});
    // The contract break is a bug to report (AGENTS.md §5): it propagates.
    await expectLater(viewModel.retry(), throwsA(isA<TypeError>()));

    // But the page is usable, and says what happened.
    expect(viewModel.busy, isFalse);
    expect(viewModel.error, isA<UnexpectedResponseException>());
  });

  test('follows the session\'s error after it opened', () async {
    final backend = FakeBackend()
      ..on('GET', '/auth/config', authConfig())
      ..on('GET', '/me', problem(401, 'unauthorized'), status: 401);
    final dependencies = testDependencies(backend: backend);
    await dependencies.auth.refresh();
    final viewModel = _viewModel(dependencies);
    var notified = 0;
    viewModel.addListener(() => notified++);
    expect(viewModel.error, isNull);

    backend.on('GET', '/me', problem(503, 'unavailable'), status: 503);
    await dependencies.auth.refresh();

    expect(viewModel.error, isA<ApiUnavailableException>());
    expect(notified, greaterThan(0));

    // Changing server forgets it.
    await viewModel.changeServer();
    expect(viewModel.error, isNull);
    viewModel.dispose();
  });

  test('the server\'s refusal wins over the session\'s error', () async {
    final backend = FakeBackend()
      ..on('GET', '/auth/config', problem(503, 'unavailable'), status: 503);
    final dependencies = testDependencies(backend: backend, web: true);
    await dependencies.auth.refresh();
    final viewModel = _viewModel(dependencies, error: 'no_role');
    expect(
      viewModel.error,
      isA<SignInRefusedException>().having((e) => e.code, 'code', 'no_role'),
    );
  });
}
