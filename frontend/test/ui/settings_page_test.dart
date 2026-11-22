import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:kanbot/data/services/server_store.dart';
import 'package:kanbot/data/services/token_store.dart';
import 'package:kanbot/routing/router.dart';
import 'package:kanbot/ui/core/messages.dart';
import 'package:kanbot/ui/features/auth/login_page.dart';
import 'package:kanbot/ui/features/auth/server_page.dart';
import 'package:shad/shad.dart';

import '../helpers/fake_backend.dart';
import '../helpers/pump.dart';
import '../helpers/test_dependencies.dart';

void main() {
  testWidgets('shows the user, with telemetry off by default', (tester) async {
    final dependencies = await signedIn(FakeBackend(), user: me(role: 'admin'));
    await pumpApp(tester, dependencies, location: Routes.settings);

    expect(find.text('Alice · ${Messages.platformAdmin}'), findsOneWidget);
    final toggle = tester.widget<ShadSwitch>(find.byType(ShadSwitch));
    expect(toggle.value, isFalse);
    expect(toggle.enabled, isTrue);
  });

  testWidgets('the telemetry switch sets the preference', (tester) async {
    final backend = FakeBackend();
    final dependencies = await signedIn(backend);
    backend.on('PUT', '/me/preferences', me(telemetryOptIn: true));
    await pumpApp(tester, dependencies, location: Routes.settings);

    await tester.tap(find.byType(ShadSwitch));
    await tester.pumpAndSettle();

    expect(jsonDecode(backend.sent('PUT', '/me/preferences').single.body), {
      'telemetry_opt_in': true,
    });
    expect(tester.widget<ShadSwitch>(find.byType(ShadSwitch)).value, isTrue);
  });

  testWidgets('a failed change says so and keeps the setting', (tester) async {
    final backend = FakeBackend();
    final dependencies = await signedIn(backend);
    backend.on(
      'PUT',
      '/me/preferences',
      problem(503, 'unavailable'),
      status: 503,
    );
    await pumpApp(tester, dependencies, location: Routes.settings);

    await tester.tap(find.byType(ShadSwitch));
    await tester.pumpAndSettle();

    expect(find.textContaining('busy or not ready'), findsOneWidget);
    expect(tester.widget<ShadSwitch>(find.byType(ShadSwitch)).value, isFalse);
  });

  testWidgets('without a relay, the switch is off and disabled', (
    tester,
  ) async {
    final backend = FakeBackend()
      ..on('GET', '/auth/config', authConfig(telemetryAvailable: false))
      ..on('GET', '/me', me());
    final dependencies = testDependencies(backend: backend);
    await dependencies.auth.refresh();
    await pumpApp(tester, dependencies, location: Routes.settings);

    expect(find.text(Messages.telemetryUnavailable), findsOneWidget);
    expect(tester.widget<ShadSwitch>(find.byType(ShadSwitch)).enabled, isFalse);
  });

  testWidgets('signing out returns to the login page', (tester) async {
    final backend = FakeBackend();
    final dependencies = await signedIn(backend);
    backend.on('POST', '/auth/logout', {'logout_url': null});
    await pumpApp(tester, dependencies, location: Routes.settings);

    await tester.tap(find.text(Messages.signOut));
    await tester.pumpAndSettle();

    expect(find.byType(LoginPage), findsOneWidget);
    expect(await TokenStore().read(server: testServer), isNull);
  });

  testWidgets('changing server signs out and asks for one', (tester) async {
    final backend = FakeBackend();
    final dependencies = await signedIn(backend);
    await ServerStore().write(testServer);
    backend.on('POST', '/auth/logout', {'logout_url': null});
    await pumpApp(tester, dependencies, location: Routes.settings);

    await tester.tap(find.text(Messages.changeServer));
    await tester.pumpAndSettle();

    expect(find.byType(ServerPage), findsOneWidget);
    expect(backend.sent('POST', '/auth/logout'), hasLength(1));
    expect(await ServerStore().read(release: false), isNull);
  });
}
