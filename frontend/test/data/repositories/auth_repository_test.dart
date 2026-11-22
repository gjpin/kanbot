import 'dart:convert';
import 'dart:io';

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

/// What some other web server answers for every path.
http.Response _html() => http.Response(
  '<!doctype html><title>Welcome</title>',
  200,
  headers: {'content-type': 'text/html'},
);

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

    final Matcher notKanbot = isA<Failure<void>>().having(
      (f) => f.error,
      'error',
      isA<NotKanbotServerException>(),
    );

    for (final path in ['/auth/config', '/me']) {
      test('a page that is not JSON at $path is not a kanbot server', () async {
        final backend = FakeBackend()
          ..on('GET', '/auth/config', authConfig())
          ..on('GET', '/me', me())
          ..handle('GET', path, (_) => _html());
        final auth = testDependencies(backend: backend).auth;

        expect(await auth.refresh(), notKanbot);

        expect(auth.status, AuthStatus.signedOut);
        expect(auth.lastError, isA<NotKanbotServerException>());
      });
    }

    test('a sign-in URL that is not a URL is not a kanbot server', () async {
      final backend = FakeBackend()
        ..on('GET', '/auth/config', {
          ...authConfig(),
          'login_url': 'http://[::1',
        });
      final auth = testDependencies(backend: backend).auth;
      expect(await auth.refresh(), notKanbot);
      expect(auth.status, AuthStatus.signedOut);
    });

    for (final path in ['/auth/config', '/me']) {
      test(
        'JSON that breaks the contract at $path throws, signed out',
        () async {
          final backend = FakeBackend()
            ..on('GET', '/auth/config', authConfig())
            ..on('GET', '/me', me())
            ..on('GET', path, {'hello': 'world'});
          final auth = testDependencies(backend: backend).auth;

          // A bug to report (AGENTS.md §5), never handled as an outcome.
          await expectLater(auth.refresh(), throwsA(isA<TypeError>()));

          expect(auth.status, AuthStatus.signedOut);
          expect(auth.lastError, isA<UnexpectedResponseException>());
        },
      );
    }
  });

  group('changing server', () {
    test('forgets the old server\'s error', () async {
      final backend = FakeBackend()
        ..on('GET', '/auth/config', problem(503, 'unavailable'), status: 503);
      final auth = testDependencies(backend: backend).auth;
      await auth.refresh();
      expect(auth.lastError, isA<ApiUnavailableException>());

      await auth.forgetServer();

      expect(auth.lastError, isNull);
      expect(auth.server, isNull);
      expect(auth.status, AuthStatus.signedOut);
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
      for (final answer in [
        'dev.sideral.kanbot:/other?code=kbc_x',
        'other.app:/auth/done?code=kbc_x',
        'https://evil.example/auth/done?code=kbc_x',
        'dev.sideral.kanbot:/auth/done?code=',
      ]) {
        webAuth.answer = (_) => Uri.parse(answer);
        final auth = testDependencies(backend: backend, webAuth: webAuth).auth;
        final result = await auth.signIn();
        expect(
          result,
          isA<Failure<void>>().having(
            (f) => f.error,
            'error',
            isA<SignInRefusedException>(),
          ),
          reason: answer,
        );
      }
      expect(backend.sent('POST', '/auth/token'), isEmpty);
    });

    test('a failing browser hand-off is a failure', () async {
      webAuth.answer = (_) => throw const SignInFailedException();
      final auth = testDependencies(backend: backend, webAuth: webAuth).auth;
      expect(
        await auth.signIn(),
        isA<Failure<void>>().having(
          (f) => f.error,
          'error',
          isA<SignInFailedException>(),
        ),
      );
    });

    test('a sign-in page on another site is never opened', () async {
      backend.on('GET', '/auth/config', {
        ...authConfig(),
        'login_url': 'https://evil.example/auth/login',
      });
      final auth = testDependencies(backend: backend, webAuth: webAuth).auth;
      expect(
        await auth.signIn(),
        isA<Failure<void>>().having(
          (f) => f.error,
          'error',
          isA<NotKanbotServerException>(),
        ),
      );
      expect(webAuth.opened, isEmpty);
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

    test('a server that cannot be asked is a failure', () async {
      backend.on(
        'GET',
        '/auth/config',
        problem(503, 'unavailable'),
        status: 503,
      );
      final auth = testDependencies(backend: backend, webAuth: webAuth).auth;
      expect(
        await auth.signIn(),
        isA<Failure<void>>().having(
          (f) => f.error,
          'error',
          isA<ApiUnavailableException>(),
        ),
      );
      expect(webAuth.opened, isEmpty);
    });

    test('a token answer that is not JSON is not a kanbot server', () async {
      backend.handle('POST', '/auth/token', (_) => _html());
      final auth = testDependencies(backend: backend, webAuth: webAuth).auth;
      final result = await auth.signIn();
      expect(
        result,
        isA<Failure<void>>().having(
          (f) => f.error,
          'error',
          isA<NotKanbotServerException>(),
        ),
      );
      expect(await TokenStore().read(), isNull);
    });

    test(
      'a sign-in answer that breaks the contract throws, with a reason',
      () async {
        backend.on('GET', '/auth/config', {'hello': 'world'});
        final auth = testDependencies(backend: backend, webAuth: webAuth).auth;
        await expectLater(auth.signIn(), throwsA(isA<TypeError>()));
        expect(auth.status, AuthStatus.signedOut);
        expect(auth.lastError, isA<UnexpectedResponseException>());
        expect(webAuth.opened, isEmpty);
      },
    );

    test('no loopback port is a failed sign-in, not an error', () async {
      final dependencies = testDependencies(backend: backend);
      final auth = AuthRepository(
        connection: dependencies.connection,
        web: false,
        webAuth: webAuth,
        nativeRedirect: () =>
            loopbackRedirect(() async => throw const SocketException('in use')),
        navigate: (_) {},
      );
      expect(
        await auth.signIn(),
        isA<Failure<void>>().having(
          (f) => f.error,
          'error',
          isA<SignInFailedException>(),
        ),
      );
      expect(webAuth.opened, isEmpty);
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

    test('a logout URL that is not a web page is ignored', () async {
      for (final logoutUrl in [
        'javascript:alert(1)',
        'http://idp.example.com/logout',
        'https://user:pass@idp.example.com/logout',
        '/relative',
        // A DNS name, not 127.0.0.0/8: plain http is refused.
        'http://127.attacker.example/logout',
      ]) {
        final backend = FakeBackend()
          ..on('GET', '/auth/config', authConfig())
          ..on('GET', '/me', me())
          ..on('POST', '/auth/logout', {'logout_url': logoutUrl});
        final navigations = <Uri>[];
        final auth = testDependencies(
          backend: backend,
          web: true,
          navigations: navigations,
        ).auth;
        await auth.refresh();
        await auth.signOut();
        expect(auth.status, AuthStatus.signedOut, reason: logoutUrl);
        expect(navigations, isEmpty, reason: logoutUrl);
      }
    });
  });

  test('a logout URL may be plain http on a loopback address', () {
    for (final url in [
      'http://localhost:9000/logout',
      'http://127.0.0.2/logout',
      'http://[::1]:9000/logout',
      'https://127.example.com/logout',
    ]) {
      expect(isLogoutUrl(Uri.parse(url)), isTrue, reason: url);
    }
  });

  group('signing out ends the session whatever the server answers:', () {
    test('a page that is not JSON', () async {
      final backend = FakeBackend();
      final dependencies = await signedIn(backend);
      backend.handle('POST', '/auth/logout', (_) => _html());

      await dependencies.auth.signOut();

      expect(dependencies.auth.status, AuthStatus.signedOut);
      expect(await TokenStore().read(), isNull);
    });

    test('JSON that breaks the contract', () async {
      final backend = FakeBackend();
      final dependencies = await signedIn(backend);
      backend.on('POST', '/auth/logout', {'logout_url': 5});

      // A bug to report (AGENTS.md §5); the session ends anyway.
      await expectLater(dependencies.auth.signOut(), throwsA(isA<TypeError>()));

      expect(dependencies.auth.status, AuthStatus.signedOut);
      expect(await TokenStore().read(), isNull);
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
