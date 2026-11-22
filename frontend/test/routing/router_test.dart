import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:kanbot/config/dependencies.dart';
import 'package:kanbot/data/repositories/auth_repository.dart';
import 'package:kanbot/data/services/server_store.dart';
import 'package:kanbot/main.dart';
import 'package:kanbot/routing/router.dart';
import 'package:kanbot/ui/core/messages.dart';
import 'package:kanbot/ui/core/not_found_page.dart';
import 'package:kanbot/ui/features/auth/loading_page.dart';
import 'package:kanbot/ui/features/auth/login_page.dart';
import 'package:kanbot/ui/features/auth/server_page.dart';
import 'package:kanbot/ui/features/organizations/organization_page.dart';
import 'package:kanbot/ui/features/organizations/organizations_page.dart';
import 'package:kanbot/ui/features/settings/settings_page.dart';
import 'package:mockito/annotations.dart';
import 'package:mockito/mockito.dart';

import '../helpers/fake_backend.dart';
import '../helpers/pump.dart';
import '../helpers/test_dependencies.dart';
import 'router_test.mocks.dart';

/// Every route that needs a signed-in user.
const List<String> protectedRoutes = [
  Routes.home,
  Routes.teams,
  Routes.audit,
  Routes.settings,
  '/organizations/$orgId',
  '/teams/$teamId',
];

@GenerateMocks([ServerStore])
void main() {
  group('redirect', () {
    String? go(
      String location, {
      bool starting = false,
      bool connected = true,
      AuthStatus? status,
    }) => redirect(
      location: Uri.parse(location),
      starting: starting,
      connected: connected,
      status: status ?? AuthStatus.signedIn,
    );

    test('without a server, everything goes to the server page', () {
      for (final status in AuthStatus.values) {
        expect(go('/teams', connected: false, status: status), Routes.server);
        expect(go(Routes.server, connected: false, status: status), isNull);
        expect(
          go('/loading?from=%2Fteams', connected: false, status: status),
          Routes.server,
        );
      }
    });

    test('while the stored server is read, the loading page shows', () {
      for (final status in AuthStatus.values) {
        final loading = go(
          '/teams',
          starting: true,
          connected: false,
          status: status,
        );
        expect(loading, '/loading?from=%2Fteams');
        expect(
          go(Routes.server, starting: true, connected: false, status: status),
          '/loading?from=%2Fserver',
        );
        expect(
          go(loading!, starting: true, connected: false, status: status),
          isNull,
        );
      }
      // Connected: the session decides, as without a start.
      expect(go('/loading?from=%2Fteams', starting: true), '/teams');
    });

    test('while loading, the loading page remembers where to go', () {
      final loading = go('/teams/x?y=1', status: AuthStatus.unknown);
      expect(loading, '/loading?from=%2Fteams%2Fx%3Fy%3D1');
      expect(go(loading!, status: AuthStatus.unknown), isNull);
      expect(go(loading, status: AuthStatus.signedIn), '/teams/x?y=1');
      expect(go(loading, status: AuthStatus.signedOut), Routes.login);
      expect(
        go(
          '/loading?from=%2Flogin%3Ferror%3Dno_role',
          status: AuthStatus.signedOut,
        ),
        '/login?error=no_role',
      );
    });

    test('"from" never leads out of the app', () {
      for (final from in [
        'https://evil.example.com/',
        '//evil.example.com/x',
        'javascript:alert(1)',
        'teams',
        ':::',
        r'/\evil.example.com',
        '/loading?from=/loading',
      ]) {
        expect(
          go(
            Uri(
              path: Routes.loading,
              queryParameters: {'from': from},
            ).toString(),
          ),
          Routes.home,
          reason: from,
        );
      }
    });

    test('signed out: public pages only', () {
      for (final route in protectedRoutes) {
        expect(
          go(route, status: AuthStatus.signedOut),
          Routes.login,
          reason: route,
        );
      }
      expect(go(Routes.login, status: AuthStatus.signedOut), isNull);
      // Connected: the server is chosen.
      expect(go(Routes.server, status: AuthStatus.signedOut), Routes.login);
      expect(go('/login?error=x', status: AuthStatus.signedOut), isNull);
    });

    test('signed in: public pages go home', () {
      for (final route in protectedRoutes) {
        expect(go(route), isNull, reason: route);
      }
      expect(go(Routes.login), Routes.home);
      expect(go(Routes.server), Routes.home);
    });
  });

  group('a signed-out user cannot reach', () {
    for (final route in protectedRoutes) {
      testWidgets(route, (tester) async {
        final backend = FakeBackend()
          ..on('GET', '/auth/config', authConfig())
          ..on('GET', '/me', problem(401, 'unauthorized'), status: 401);
        final dependencies = testDependencies(backend: backend);
        await dependencies.auth.refresh();

        await tester.pumpWidget(
          KanbotApp(
            router: createRouter(
              dependencies: dependencies,
              initialLocation: route,
            ),
          ),
        );
        await tester.pumpAndSettle();

        expect(find.byType(LoginPage), findsOneWidget);
        // Only the sign-in calls: the page never loaded.
        expect(backend.requests.map((request) => request.url.path).toSet(), {
          '/auth/config',
          '/me',
        });
      });
    }
  });

  testWidgets('a native app without a server asks for one', (tester) async {
    await tester.pumpWidget(
      KanbotApp(
        router: createRouter(
          dependencies: testDependencies(connected: false),
          initialLocation: Routes.settings,
        ),
      ),
    );
    await tester.pumpAndSettle();
    expect(find.byType(ServerPage), findsOneWidget);
  });

  testWidgets('a native app with a stored server never asks for one', (
    tester,
  ) async {
    final backend = FakeBackend()
      ..on('GET', '/auth/config', authConfig())
      ..on('GET', '/me', problem(401, 'unauthorized'), status: 401);
    // Secure storage answers when the test says so (a slow keychain, a
    // locked keyring).
    final stored = Completer<Uri?>();
    final store = MockServerStore();
    when(store.read(release: false)).thenAnswer((_) => stored.future);
    final base = testDependencies(backend: backend, connected: false);
    final dependencies = AppDependencies(
      web: false,
      release: false,
      connection: base.connection,
      auth: base.auth,
      newConnection: base.newConnection,
      serverStore: store,
    );
    // As main does: started before the first frame.
    final started = dependencies.start();
    await tester.pumpWidget(
      KanbotApp(
        router: createRouter(
          dependencies: dependencies,
          initialLocation: Routes.settings,
        ),
      ),
    );
    for (var frame = 0; frame < 10; frame++) {
      expect(find.byType(LoadingPage), findsOneWidget, reason: 'frame $frame');
      expect(find.byType(ServerPage), findsNothing, reason: 'frame $frame');
      await tester.pump(const Duration(milliseconds: 100));
    }

    stored.complete(testServer);
    await started;
    await tester.pumpAndSettle();

    expect(find.byType(LoginPage), findsOneWidget);
    expect(dependencies.connection.baseUrl, testServer);
  });

  testWidgets('shows the loading page until the session is known', (
    tester,
  ) async {
    final backend = FakeBackend()
      ..on('GET', '/auth/config', authConfig())
      ..on('GET', '/me', me());
    final dependencies = testDependencies(backend: backend);
    await tester.pumpWidget(
      KanbotApp(
        router: createRouter(
          dependencies: dependencies,
          initialLocation: Routes.settings,
        ),
      ),
    );
    await tester.pump();
    expect(find.byType(LoadingPage), findsOneWidget);

    await dependencies.auth.refresh();
    await tester.pumpAndSettle();
    expect(find.byType(SettingsPage), findsOneWidget);
  });

  group('signed in', () {
    Future<FakeBackend> pump(WidgetTester tester, String location) async {
      final backend = FakeBackend()..on('GET', '/organizations', <Object?>[]);
      final dependencies = await signedIn(backend);
      await tester.pumpWidget(
        KanbotApp(
          router: createRouter(
            dependencies: dependencies,
            initialLocation: location,
          ),
        ),
      );
      await tester.pumpAndSettle();
      return backend;
    }

    for (final location in [
      '/no/such/page',
      '/teams/not-a-uuid',
      '/organizations/abcdef00-0000-4000-8000-00000000000',
    ]) {
      testWidgets('$location shows not found', (tester) async {
        final backend = await pump(tester, location);
        expect(find.byType(NotFoundPage), findsOneWidget);
        expect(backend.requests.map((r) => r.url.path).toSet(), {
          '/auth/config',
          '/me',
        });
      });
    }

    testWidgets('IDs in links may be in upper case', (tester) async {
      final backend = FakeBackend()
        ..on('GET', '/auth/config', authConfig())
        ..on('GET', '/me', me())
        ..on('GET', '/organizations/$orgId', organization())
        ..on('GET', '/organizations/$orgId/admins', <Object?>[])
        ..on('GET', '/organizations/$orgId/teams', <Object?>[]);
      await pumpApp(
        tester,
        await signedIn(backend),
        location: '/organizations/${orgId.toUpperCase()}',
      );
      expect(find.byType(OrganizationPage), findsOneWidget);
      expect(backend.sent('GET', '/organizations/$orgId'), hasLength(1));
    });

    testWidgets('not found leads back home', (tester) async {
      await pump(tester, '/no/such/page');
      await tester.tap(find.text(Messages.goHome));
      await tester.pumpAndSettle();
      expect(find.byType(OrganizationsPage), findsOneWidget);
    });

    testWidgets('the login page goes home', (tester) async {
      await pump(tester, Routes.login);
      expect(find.byType(OrganizationsPage), findsOneWidget);
    });
  });
}
