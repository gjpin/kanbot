import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:kanbot/config/dependencies.dart';
import 'package:kanbot/config/telemetry.dart';
import 'package:kanbot/data/repositories/auth_repository.dart';
import 'package:kanbot/data/services/server_store.dart';
import 'package:kanbot/data/services/token_store.dart';
import 'package:kanbot/data/services/web_auth.dart';
import 'package:kanbot/utils/result.dart';
import 'package:mockito/annotations.dart';
import 'package:mockito/mockito.dart';

import '../helpers/fake_backend.dart';
import '../helpers/test_dependencies.dart';
import 'dependencies_test.mocks.dart';

final Uri _other = Uri.parse('https://other.example.com/');

/// A server answering every `GET /auth/config` and `GET /me` (signed out).
FakeBackend _signedOutBackend() => FakeBackend()
  ..on('GET', '/auth/config', authConfig())
  ..on('GET', '/me', problem(401, 'unauthorized'), status: 401);

/// [base] with [store] as its server store and [defaultServer].
AppDependencies _withStore(
  AppDependencies base,
  ServerStore store, {
  Uri? defaultServer,
}) => AppDependencies(
  web: false,
  release: false,
  connection: base.connection,
  auth: base.auth,
  newConnection: base.newConnection,
  serverStore: store,
  defaultServer: defaultServer,
);

@GenerateMocks([ServerStore])
void main() {
  test('the web app knows its server before the first frame', () {
    final dependencies = testDependencies(
      backend: FakeBackend(),
      web: true,
      connected: false,
    );
    expect(dependencies.connection.isConnected, isFalse);

    dependencies.connectWeb(
      Uri.parse('https://kanbot.example.com:8443/organizations/x?y=1'),
    );

    expect(
      dependencies.connection.baseUrl,
      Uri.parse('https://kanbot.example.com:8443/'),
    );
  });

  test('start connects the web app once, and loads the session', () async {
    final backend = FakeBackend()
      ..on('GET', '/auth/config', authConfig())
      ..on('GET', '/me', me());
    final dependencies = testDependencies(
      backend: backend,
      web: true,
      connected: false,
    );
    final page = Uri.parse('https://kanbot.example.com/');
    dependencies.connectWeb(page);
    await dependencies.start(page: page);
    expect(dependencies.auth.user?.displayName, 'Alice');
    expect(dependencies.starting.value, isFalse);
  });

  group('native start', () {
    test('connects to the stored server and loads the session', () async {
      final backend = FakeBackend()
        ..on('GET', '/auth/config', authConfig())
        ..on('GET', '/me', me());
      final dependencies = testDependencies(
        backend: backend,
        connected: false,
        storage: {
          'server_url': testServer.toString(),
          'auth_token': TokenStore.entry(testServer, 'kbs_x'),
        },
        defaultServer: _other,
      );

      final started = dependencies.start();
      expect(dependencies.starting.value, isTrue);
      await started;

      expect(dependencies.starting.value, isFalse);
      expect(dependencies.connection.baseUrl, testServer);
      expect(dependencies.auth.status, AuthStatus.signedIn);
      expect(
        backend.sent('GET', '/me').single.headers['authorization'],
        'Bearer kbs_x',
      );
    });

    test('forgets an invalid stored server and uses the default', () async {
      final backend = _signedOutBackend();
      final dependencies = testDependencies(
        backend: backend,
        connected: false,
        // Plain http to a host that is not loopback.
        storage: {'server_url': 'http://kanbot.example.com/'},
        defaultServer: _other,
      );

      await dependencies.start();

      expect(dependencies.connection.baseUrl, _other);
      expect(await ServerStore().read(release: false), isNull);
      expect(dependencies.auth.status, AuthStatus.signedOut);
      expect(backend.sent('GET', '/auth/config').single.url.host, _other.host);
    });

    test('never sends the token of a forgotten server to another', () async {
      // The stored server is no longer valid, but its session token is
      // still stored: the default server must not receive it.
      final stale = Uri.parse('http://kanbot.example.com/');
      final backend = _signedOutBackend();
      final dependencies = testDependencies(
        backend: backend,
        connected: false,
        storage: {
          'server_url': stale.toString(),
          'auth_token': TokenStore.entry(stale, 'kbs_old'),
        },
        defaultServer: _other,
      );

      await dependencies.start();

      expect(dependencies.connection.baseUrl, _other);
      expect(backend.requests, isNotEmpty);
      for (final request in backend.requests) {
        expect(request.headers.containsKey('authorization'), isFalse);
      }
    });

    test('without a stored or default server, asks for one', () async {
      final backend = FakeBackend();
      final dependencies = testDependencies(
        backend: backend,
        connected: false,
        storage: {'server_url': 'not a url'},
      );

      await dependencies.start();

      expect(dependencies.connection.isConnected, isFalse);
      expect(dependencies.starting.value, isFalse);
      expect(dependencies.auth.status, AuthStatus.unknown);
      expect(backend.requests, isEmpty);
    });

    test('falls back to the default server when none is stored', () async {
      final dependencies = testDependencies(
        backend: _signedOutBackend(),
        connected: false,
        defaultServer: _other,
      );
      await dependencies.start();
      expect(dependencies.connection.baseUrl, _other);
      expect(dependencies.auth.status, AuthStatus.signedOut);
    });

    test('secure storage failing falls back to the default server', () async {
      final store = MockServerStore();
      when(store.read(release: false))
          .thenAnswer((_) async => throw PlatformException(code: 'locked'));
      final dependencies = _withStore(
        testDependencies(backend: _signedOutBackend(), connected: false),
        store,
        defaultServer: _other,
      );

      await dependencies.start();

      expect(dependencies.starting.value, isFalse);
      expect(dependencies.connection.baseUrl, _other);
      expect(dependencies.auth.status, AuthStatus.signedOut);
    });

    test(
      'secure storage failing without a default asks for a server',
      () async {
        final store = MockServerStore();
        when(store.read(release: false))
            .thenAnswer((_) async => throw PlatformException(code: 'locked'));
        final backend = FakeBackend();
        final dependencies = _withStore(
          testDependencies(backend: backend, connected: false),
          store,
        );

        await dependencies.start();

        expect(dependencies.starting.value, isFalse);
        expect(dependencies.connection.isConnected, isFalse);
        expect(backend.requests, isEmpty);
      },
    );

    test(
      'a server the user chooses meanwhile wins over the stored one',
      () async {
        final backend = FakeBackend();
        final dependencies = testDependencies(
          backend: backend,
          connected: false,
          storage: {'server_url': testServer.toString()},
        );

        final started = dependencies.start();
        // The server page's choice, while secure storage is still reading.
        dependencies.connection.connect(_other);
        await started;

        expect(dependencies.connection.baseUrl, _other);
        expect(dependencies.starting.value, isFalse);
        // Loading the session is the server page's job then.
        expect(backend.requests, isEmpty);
      },
    );

    test('an answer that is not JSON ends signed out, not loading', () async {
      final backend = FakeBackend()
        ..handle(
          'GET',
          '/auth/config',
          (_) => http.Response(
            '<!doctype html><title>Welcome</title>',
            200,
            headers: {'content-type': 'text/html'},
          ),
        );
      final dependencies = testDependencies(
        backend: backend,
        connected: false,
        defaultServer: _other,
      );

      await dependencies.start();

      expect(dependencies.auth.status, AuthStatus.signedOut);
      expect(dependencies.auth.lastError, isA<NotKanbotServerException>());
    });

    test('an answer that breaks the contract throws, signed out', () async {
      final backend = FakeBackend()
        ..on('GET', '/auth/config', {'hello': 'world'});
      final dependencies = testDependencies(
        backend: backend,
        connected: false,
        defaultServer: _other,
      );

      // A bug (AGENTS.md §5): main leaves it to the uncaught-error reporter.
      await expectLater(dependencies.start(), throwsA(isA<TypeError>()));

      expect(dependencies.auth.status, AuthStatus.signedOut);
      expect(dependencies.auth.lastError, isA<UnexpectedResponseException>());
    });
  });

  group('AppDependencies.create', () {
    tearDown(() => debugDefaultTargetPlatformOverride = null);

    test('only native apps keep a server; nothing is connected yet', () {
      for (final web in [false, true]) {
        final dependencies = AppDependencies.create(
          web: web,
          release: true,
          telemetry: silentTelemetry(),
        );
        expect(dependencies.serverStore == null, web, reason: 'web: $web');
        expect(dependencies.connection.isConnected, isFalse);
        expect(dependencies.starting.value, isFalse);
        expect(dependencies.auth.status, AuthStatus.unknown);
      }
    });

    test('checking another server never carries the session token', () async {
      final backend = FakeBackend()..on('GET', '/auth/config', authConfig());
      final dependencies = testDependencies(
        backend: backend,
        storage: {'auth_token': TokenStore.entry(testServer, 'kbs_secret')},
      );

      final probe = dependencies.newConnection()..connect(testServer);
      await probe.api.auth.config();
      await dependencies.connection.api.auth.config();

      final sent = backend.sent('GET', '/auth/config');
      expect(sent[0].headers.containsKey('authorization'), isFalse);
      expect(sent[1].headers['authorization'], 'Bearer kbs_secret');
    });

    test('telemetry follows the user\'s consent', () async {
      final endpoints = <Uri>[];
      final exporters = TelemetryExporters(
        create: (endpoint, _) {
          endpoints.add(endpoint);
          return (spans: SilentExporter(), logs: SilentExporter());
        },
      );
      final backend = FakeBackend()
        ..on('GET', '/auth/config', authConfig())
        ..on('GET', '/me', me(telemetryOptIn: true));
      final dependencies = testDependencies(
        backend: backend,
        storage: {'auth_token': TokenStore.entry(testServer, 'kbs_x')},
        telemetry: exporters,
      );

      await dependencies.auth.refresh();
      await pumpEventQueue();

      expect(exporters.enabled, isTrue);
      expect(endpoints, [Uri.parse('https://kanbot.example.com/telemetry')]);
    });

    for (final (platform, redirectUri, callback) in [
      (
        TargetPlatform.android,
        'dev.sideral.kanbot:/auth/done',
        'dev.sideral.kanbot',
      ),
      (
        TargetPlatform.iOS,
        'dev.sideral.kanbot:/auth/done',
        'dev.sideral.kanbot',
      ),
      (
        TargetPlatform.macOS,
        'dev.sideral.kanbot:/auth/done',
        'dev.sideral.kanbot',
      ),
      (
        TargetPlatform.linux,
        'http://127.0.0.1:43210/auth/done',
        'http://127.0.0.1:43210',
      ),
      (
        TargetPlatform.windows,
        'http://127.0.0.1:43210/auth/done',
        'http://127.0.0.1:43210',
      ),
    ]) {
      test('${platform.name} signs in through $callback', () async {
        debugDefaultTargetPlatformOverride = platform;
        final webAuth = FakeWebAuth(
          (_) => throw const SignInCancelledException(),
        );
        final dependencies = testDependencies(
          backend: FakeBackend()..on('GET', '/auth/config', authConfig()),
          webAuth: webAuth,
          freePort: () async => 43210,
        );

        await dependencies.auth.signIn();

        expect(webAuth.callbacks, [callback]);
        expect(
          webAuth.opened.single.queryParameters['redirect_uri'],
          redirectUri,
        );
      });
    }

    test('no free loopback port is a failed sign-in', () async {
      debugDefaultTargetPlatformOverride = TargetPlatform.linux;
      final webAuth = FakeWebAuth(
        (_) => throw const SignInCancelledException(),
      );
      final dependencies = testDependencies(
        backend: FakeBackend()..on('GET', '/auth/config', authConfig()),
        webAuth: webAuth,
        freePort: () async =>
            throw const SocketException('Address already in use'),
      );

      final result = await dependencies.auth.signIn();

      expect(
        result,
        isA<Failure<void>>().having(
          (f) => f.error,
          'error',
          isA<SignInFailedException>(),
        ),
      );
      expect(webAuth.opened, isEmpty);
    });
  });
}
