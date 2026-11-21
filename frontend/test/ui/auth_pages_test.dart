import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:kanbot/data/repositories/auth_repository.dart';
import 'package:kanbot/data/services/server_store.dart';
import 'package:kanbot/data/services/token_store.dart';
import 'package:kanbot/routing/router.dart';
import 'package:kanbot/ui/core/messages.dart';
import 'package:kanbot/ui/features/auth/login_page.dart';
import 'package:kanbot/ui/features/auth/server_page.dart';
import 'package:kanbot/ui/features/organizations/organizations_page.dart';
import 'package:shad/shad.dart';

import '../helpers/fake_backend.dart';
import '../helpers/pump.dart';
import '../helpers/test_dependencies.dart';

void main() {
  group('server page', () {
    testWidgets('refuses addresses that are not https', (tester) async {
      final backend = FakeBackend();
      await pumpApp(
        tester,
        testDependencies(backend: backend, connected: false),
      );

      await tester.enterText(
        find.byType(EditableText),
        'http://kanbot.example.com',
      );
      await tester.tap(find.text(Messages.connect));
      await tester.pumpAndSettle();

      expect(find.text(Messages.invalidServer), findsOneWidget);
      expect(backend.requests, isEmpty);
    });

    testWidgets('says when the server is not a kanbot server', (tester) async {
      final backend = FakeBackend()
        ..on('GET', '/auth/config', problem(404, 'not_found'), status: 404);
      final dependencies = testDependencies(backend: backend, connected: false);
      await pumpApp(tester, dependencies);

      await tester.enterText(
        find.byType(EditableText),
        'https://other.example.com',
      );
      await tester.tap(find.text(Messages.connect));
      await tester.pumpAndSettle();

      expect(find.byType(ServerPage), findsOneWidget);
      expect(find.textContaining('no longer exists'), findsOneWidget);
      expect(dependencies.connection.isConnected, isFalse);
      expect(await ServerStore().read(release: false), isNull);
    });

    testWidgets('connects, remembers the server, then asks to sign in', (
      tester,
    ) async {
      final backend = FakeBackend()
        ..on('GET', '/auth/config', authConfig())
        ..on('GET', '/me', problem(401, 'unauthorized'), status: 401);
      final dependencies = testDependencies(backend: backend, connected: false);
      await pumpApp(tester, dependencies);

      await tester.enterText(
        find.byType(EditableText),
        ' https://kanbot.example.com ',
      );
      await tester.tap(find.text(Messages.connect));
      await tester.pumpAndSettle();

      expect(find.byType(LoginPage), findsOneWidget);
      expect(dependencies.connection.baseUrl, testServer);
      expect(await ServerStore().read(release: true), testServer);
      expect(
        find.text('${Messages.server}: kanbot.example.com'),
        findsOneWidget,
      );
    });
  });

  group('login page', () {
    Future<FakeBackend> signedOut(
      WidgetTester tester, {
      FakeWebAuth? webAuth,
      bool web = false,
      String location = Routes.login,
    }) async {
      final backend = FakeBackend()
        ..on('GET', '/auth/config', authConfig())
        ..on('GET', '/me', problem(401, 'unauthorized'), status: 401);
      final dependencies = testDependencies(
        backend: backend,
        webAuth: webAuth,
        web: web,
      );
      await dependencies.auth.refresh();
      await pumpApp(tester, dependencies, location: location);
      return backend;
    }

    testWidgets('shows why the server refused a web sign-in', (tester) async {
      await signedOut(tester, web: true, location: '/login?error=no_role');
      expect(find.text(Messages.signInRefused('no_role')), findsOneWidget);
      // The web app belongs to its server.
      expect(find.text(Messages.changeServer), findsNothing);
    });

    testWidgets('signs in through the browser', (tester) async {
      final webAuth = FakeWebAuth(
        (_) => Uri.parse('dev.sideral.kanbot:/auth/done?code=kbc_x'),
      );
      final backend = await signedOut(tester, webAuth: webAuth);
      backend
        ..on('POST', '/auth/token', {
          'session_token': 'kbs_new',
          'expires_at': '2026-12-21T00:00:00Z',
        })
        ..on('GET', '/me', me())
        ..on('GET', '/organizations', <Object?>[]);

      await tester.tap(find.widgetWithText(ShadButton, Messages.signIn));
      await tester.pumpAndSettle();

      expect(webAuth.opened, hasLength(1));
      expect(await TokenStore().read(), 'kbs_new');
      expect(find.byType(OrganizationsPage), findsOneWidget);
    });

    testWidgets('a cancelled sign-in stays on the page', (tester) async {
      await signedOut(tester);
      await tester.tap(find.widgetWithText(ShadButton, Messages.signIn));
      await tester.pumpAndSettle();
      expect(find.text(Messages.signInCancelled), findsOneWidget);
      expect(find.byType(LoginPage), findsOneWidget);
    });

    testWidgets('an unreachable server offers a retry', (tester) async {
      final backend = FakeBackend()
        ..on('GET', '/auth/config', problem(503, 'unavailable'), status: 503);
      final dependencies = testDependencies(backend: backend);
      await dependencies.auth.refresh();
      await pumpApp(tester, dependencies, location: Routes.login);
      expect(find.text(Messages.retry), findsOneWidget);

      backend
        ..on('GET', '/auth/config', authConfig())
        ..on('GET', '/me', me())
        ..on('GET', '/organizations', <Object?>[]);
      await tester.tap(find.text(Messages.retry));
      await tester.pumpAndSettle();
      expect(dependencies.auth.status, AuthStatus.signedIn);
      expect(find.byType(OrganizationsPage), findsOneWidget);
    });

    testWidgets('a native user can change server', (tester) async {
      await signedOut(tester);
      await ServerStore().write(testServer);
      await tester.tap(find.text(Messages.changeServer));
      await tester.pumpAndSettle();
      expect(find.byType(ServerPage), findsOneWidget);
      expect(await ServerStore().read(release: false), isNull);
    });
  });
}
