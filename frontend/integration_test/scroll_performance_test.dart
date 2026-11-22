import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:kanbot/routing/router.dart';
import 'package:kanbot/ui/features/audit/audit_page.dart';

import '../test/helpers/fake_backend.dart';
import '../test/helpers/pump.dart';
import '../test/helpers/test_dependencies.dart';

/// Frame timings while scrolling the audit log, the app's longest list,
/// against a scripted server (no stack needed). Run on a desktop, for
/// example `flutter test integration_test/scroll_performance_test.dart -d linux`;
/// numbers only mean something in profile mode on a real device
/// (frontend/AGENTS.md §6). The summary goes to the test's report data.
void main() {
  final binding = IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('scrolling the audit log', (tester) async {
    final backend = FakeBackend()
      ..on('GET', '/audit', {
        'entries': [
          for (var id = 500; id > 0; id--)
            {
              'id': id,
              'at': '2026-11-21T10:00:00Z',
              'actor': user(),
              'action': 'team.member_set',
              'target_type': 'team',
              'target_id': teamId,
              'policy_ids': ['builtin.team-maintainers'],
              'details': <String, Object?>{},
            },
        ],
        'next_before': null,
      });
    await pumpApp(
      tester,
      await signedIn(
        backend,
        user: me(role: 'admin', permissions: ['view_audit']),
      ),
      location: Routes.audit,
    );
    expect(find.byType(AuditPage), findsOneWidget);
    final list = find.byType(Scrollable).first;

    await binding.traceAction(() async {
      for (var i = 0; i < 3; i++) {
        await tester.fling(list, const Offset(0, -1500), 4000);
        await tester.pumpAndSettle();
      }
      await tester.fling(list, const Offset(0, 4500), 4000);
      await tester.pumpAndSettle();
    }, reportKey: 'audit_scroll_timeline');

    // Lazily built: far fewer entries exist than the list holds.
    expect(find.text('team.member_set').evaluate().length, lessThan(100));
  });
}
