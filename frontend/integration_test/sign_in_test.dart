import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:kanbot/main.dart' as app;
import 'package:kanbot/ui/core/messages.dart';
import 'package:kanbot/ui/features/auth/login_page.dart';
import 'package:kanbot/ui/features/organizations/organizations_page.dart';
import 'package:kanbot/ui/features/settings/settings_page.dart';
import 'package:shad/shad.dart';

/// Signs in on the desktop against the local stack: the system browser
/// (a stand-in that signs `alice` in at Authelia, see README.md), the
/// loopback redirect, the one-time code and the session token in the
/// platform's secret store. Run with `run_linux.sh`.
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  /// Pumps until [finder] finds something, or fails after [timeout].
  Future<void> waitFor(
    WidgetTester tester,
    Finder finder, {
    Duration timeout = const Duration(seconds: 60),
  }) async {
    final end = DateTime.now().add(timeout);
    while (finder.evaluate().isEmpty) {
      if (DateTime.now().isAfter(end)) fail('timed out waiting for $finder');
      await tester.pump(const Duration(milliseconds: 200));
    }
  }

  testWidgets('signs in through the system browser', (tester) async {
    await app.main();
    await waitFor(tester, find.byType(LoginPage));

    await tester.tap(find.widgetWithText(ShadButton, Messages.signIn));
    await waitFor(tester, find.byType(OrganizationsPage));

    await tester.tap(find.text(Messages.settings));
    await waitFor(tester, find.byType(SettingsPage));
    expect(
      find.text('Alice (admin) · ${Messages.platformAdmin}'),
      findsOneWidget,
    );

    await tester.tap(find.text(Messages.signOut));
    await waitFor(tester, find.byType(LoginPage));
  });
}
