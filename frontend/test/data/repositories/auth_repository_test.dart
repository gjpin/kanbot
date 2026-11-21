import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:kanbot/data/repositories/auth_repository.dart';
import 'package:kanbot/data/services/api_exception.dart';
import 'package:kanbot/data/services/pkce.dart';
import 'package:kanbot/data/services/token_store.dart';
import 'package:kanbot/data/services/web_auth.dart';
import 'package:kanbot/domain/models/user.dart';
import 'package:kanbot/utils/result.dart';

import '../../helpers/fake_backend.dart';
import '../../helpers/test_dependencies.dart';

void main() {
  group('refresh', () {
    test('signs in with GET /me', () async {
      final backend = FakeBackend()
        ..on('GET', '/auth/config', authConfig())
        ..on(
          'GET',
          '/me',
          me(role: 'admin', permissions: ['view_audit', 'create_team', 'x']),
        );
      final auth = testDependencies(backend: backend).auth;
      var notified = 0;
      auth.addListener(() => notified++);

      expect(auth.status, AuthStatus.unknown);
      expect(await auth.refresh(), isA<Ok<void>>());

      expect(auth.status, AuthStatus.signedIn);
      final user = auth.user!;
      expect(user.displayName, 'Alice');
      expect(user.role, PlatformRole.admin);
      // Permissions this app version does not know are left out.
      expect(user.permissions, {
        PlatformPermission.viewAudit,
        PlatformPermission.createTeam,
      });
      expect(auth.server?.loginUrl.path, '/auth/login');
      expect(auth.lastError, isNull);
      expect(notified, 1);
    });

    test('a 401 signs out and forgets the token', () async {
      final backend = FakeBackend()
        ..on('GET', '/auth/config', authConfig())
        ..on('GET', '/me', problem(401, 'unauthorized'), status: 401);
      final auth = testDependencies(
        backend: backend,
        storage: {'auth_token': 'kbs_old'},
      ).auth;

      expect(await auth.refresh(), isA<Ok<void>>());

      expect(auth.status, AuthStatus.signedOut);
      expect(auth.user, isNull);
      expect(auth.lastError, isNull);
      expect(await TokenStore().read(), isNull);
    });

    test('an unreachable server signs out with the reason', () async {
      final backend = FakeBackend()
        ..handle(
          'GET',
          '/auth/config',
          (_) => throw http.ClientException('refused'),
        );
      final auth = testDependencies(
        backend: backend,
        storage: {'auth_token': 'kbs_kept'},
      ).auth;

      final result = await auth.refresh();

      expect(result, isA<Failure<void>>());
      expect(auth.status, AuthStatus.signedOut);
      expect(auth.lastError, isA<ApiNetworkException>());
      // The token may still be good once the server is back.
      expect(await TokenStore().read(), 'kbs_kept');
    });

    test('a failing GET /me signs out with the reason', () async {
      final backend = FakeBackend()
        ..on('GET', '/auth/config', authConfig())
        ..on('GET', '/me', problem(503, 'unavailable'), status: 503);
      final auth = testDependencies(backend: backend).auth;
      expect(await auth.refresh(), isA<Failure<void>>());
      expect(auth.lastError, isA<ApiUnavailableException>());
    });
  });

  group('native sign-in', () {
    late FakeBackend backend;
    late FakeWebAuth webAuth;

    setUp(() {
      backend = FakeBackend()
        ..on('GET', '/auth/config', authConfig())
        ..on('GET', '/me', me());
      webAuth = FakeWebAuth(
        (url) => Uri.parse('dev.sideral.kanbot:/auth/done?code=kbc_one'),
      );
    });

    test('opens the server, redeems the code with the verifier', () async {
      backend.handle('POST', '/auth/token', (request) {
        final body = jsonDecode(request.body) as Map<String, Object?>;
        final challenge =
            webAuth.opened.single.queryParameters['code_challenge'];
        expect(body['code'], 'kbc_one');
        expect(Pkce.challengeOf(body['code_verifier']! as String), challenge);
        return http.Response(
          jsonEncode({
            'session_token': 'kbs_new',
            'expires_at': '2026-12-21T00:00:00Z',
          }),
          200,
          headers: {'content-type': 'application/json'},
        );
      });
      final auth = testDependencies(backend: backend, webAuth: webAuth).auth;

      expect(await auth.signIn(), isA<Ok<void>>());

      final opened = webAuth.opened.single;
      expect(
        opened.replace(query: '').toString(),
        'https://kanbot.example.com/auth/login?',
      );
      expect(opened.queryParameters, {
        'platform': 'native',
        'redirect_uri': 'dev.sideral.kanbot:/auth/done',
        'code_challenge': isA<String>(),
        'code_challenge_method': 'S256',
      });
      expect(await TokenStore().read(), 'kbs_new');
      expect(auth.status, AuthStatus.signedIn);
      // The session token, not an IdP token, authenticates from now on.
      expect(
        backend.sent('GET', '/me').last.headers['authorization'],
        'Bearer kbs_new',
      );
    });

    test('a refused sign-in reports the server\'s reason', () async {
      webAuth.answer = (_) =>
          Uri.parse('dev.sideral.kanbot:/auth/done?error=no_role');
      final auth = testDependencies(backend: backend, webAuth: webAuth).auth;

      final result = await auth.signIn();

      expect(
        result,
        isA<Failure<void>>().having(
          (failure) => failure.error,
          'error',
          isA<SignInRefusedException>().having(
            (e) => e.code,
            'code',
            'no_role',
          ),
        ),
      );
      expect(backend.sent('POST', '/auth/token'), isEmpty);
      expect(await TokenStore().read(), isNull);
    });

    test('a redirect elsewhere is refused', () async {
      webAuth.answer = (_) => Uri.parse('dev.sideral.kanbot:/other?code=kbc_x');
      final auth = testDependencies(backend: backend, webAuth: webAuth).auth;
      final result = await auth.signIn();
      expect(
        result,
        isA<Failure<void>>().having(
          (f) => f.error,
          'error',
          isA<SignInRefusedException>(),
        ),
      );
      expect(backend.sent('POST', '/auth/token'), isEmpty);
    });

    test('cancelling is a failure, not an error', () async {
      webAuth.answer = (_) => throw const SignInCancelledException();
      final auth = testDependencies(backend: backend, webAuth: webAuth).auth;
      final result = await auth.signIn();
      expect(
        result,
        isA<Failure<void>>().having(
          (f) => f.error,
          'error',
          isA<SignInCancelledException>(),
        ),
      );
    });

    test('a code the server refuses is a failure', () async {
      backend.on(
        'POST',
        '/auth/token',
        problem(400, 'bad_request'),
        status: 400,
      );
      final auth = testDependencies(backend: backend, webAuth: webAuth).auth;
      final result = await auth.signIn();
      expect(
        result,
        isA<Failure<void>>().having(
          (f) => f.error,
          'error',
          isA<ApiBadRequestException>(),
        ),
      );
      expect(await TokenStore().read(), isNull);
    });

    test('Windows and Linux use a loopback redirect', () async {
      final redirect = await loopbackRedirect(() async => 43210);
      expect(redirect.redirectUri, 'http://127.0.0.1:43210/auth/done');
      expect(redirect.callback, 'http://127.0.0.1:43210');
      final scheme = await appSchemeRedirect();
      expect(scheme.redirectUri, 'dev.sideral.kanbot:/auth/done');
      expect(scheme.callback, 'dev.sideral.kanbot');
    });
  });

  group('web', () {
    test('signs in by sending the page to the server', () async {
      final backend = FakeBackend()..on('GET', '/auth/config', authConfig());
      final navigations = <Uri>[];
      final auth = testDependencies(
        backend: backend,
        web: true,
        navigations: navigations,
      ).auth;

      expect(await auth.signIn(), isA<Ok<void>>());

      expect(navigations, [
        Uri.parse('https://kanbot.example.com/auth/login?platform=web'),
      ]);
    });

    test('signs out at the server, then at the identity provider', () async {
      final backend = FakeBackend()
        ..on('POST', '/auth/logout', {
          'logout_url': 'https://idp.example.com/logout',
        });
      final navigations = <Uri>[];
      final dependencies = await signedIn(backend, web: true);
      final auth = dependencies.auth;
      final web = testDependencies(
        backend: backend,
        web: true,
        navigations: navigations,
      ).auth;
      backend
        ..on('GET', '/auth/config', authConfig())
        ..on('GET', '/me', me());
      await web.refresh();

      await web.signOut();

      expect(web.status, AuthStatus.signedOut);
      expect(navigations, [Uri.parse('https://idp.example.com/logout')]);
      // Cookie-authenticated: the CSRF header goes along.
      expect(
        backend.sent('POST', '/auth/logout').last.headers['x-kanbot-csrf'],
        '1',
      );
      expect(auth.status, AuthStatus.signedIn);
    });
  });

  test(
    'native sign-out forgets the token even if the server is down',
    () async {
      final backend = FakeBackend();
      final dependencies = await signedIn(backend);
      backend.handle(
        'POST',
        '/auth/logout',
        (_) => throw http.ClientException('down'),
      );

      await dependencies.auth.signOut();

      expect(dependencies.auth.status, AuthStatus.signedOut);
      expect(await TokenStore().read(), isNull);
    },
  );

  test('any 401 ends the session', () async {
    final backend = FakeBackend();
    final dependencies = await signedIn(backend);
    backend.on('GET', '/teams', problem(401, 'unauthorized'), status: 401);

    await dependencies.teams.list();
    await pumpEventQueue();

    expect(dependencies.auth.status, AuthStatus.signedOut);
    expect(await TokenStore().read(), isNull);
  });

  test('telemetry consent goes to the server', () async {
    final backend = FakeBackend();
    final dependencies = await signedIn(backend);
    backend.on('PUT', '/me/preferences', me(telemetryOptIn: true));

    expect(
      await dependencies.auth.setTelemetryOptIn(optIn: true),
      isA<Ok<void>>(),
    );

    expect(dependencies.auth.user?.telemetryOptIn, isTrue);
    expect(jsonDecode(backend.sent('PUT', '/me/preferences').single.body), {
      'telemetry_opt_in': true,
    });
    backend.on(
      'PUT',
      '/me/preferences',
      problem(503, 'unavailable'),
      status: 503,
    );
    expect(
      await dependencies.auth.setTelemetryOptIn(optIn: false),
      isA<Failure<void>>(),
    );
    expect(dependencies.auth.user?.telemetryOptIn, isTrue);
  });
}
