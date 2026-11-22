import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:kanbot/routing/router.dart';
import 'package:kanbot/ui/core/messages.dart';

import '../helpers/fake_backend.dart';
import '../helpers/pump.dart';
import '../helpers/test_dependencies.dart';

Map<String, Object?> entry(int id, String action) => {
  'id': id,
  'at': '2026-11-21T10:00:00Z',
  'actor': user(),
  'action': action,
  'target_type': 'team',
  'target_id': teamId,
  'policy_ids': ['builtin.platform-admins'],
  'details': <String, Object?>{},
};

void main() {
  testWidgets('pages through the audit log', (tester) async {
    final backend = FakeBackend()
      ..handle('GET', '/audit', (request) {
        final first = request.url.queryParameters['before'] == null;
        return http.Response(
          jsonEncode({
            'entries': [
              first ? entry(9, 'team.created') : entry(3, 'team.deleted'),
            ],
            'next_before': first ? 9 : null,
          }),
          200,
          headers: {'content-type': 'application/json'},
        );
      });
    await pumpApp(
      tester,
      await signedIn(
        backend,
        user: me(role: 'admin', permissions: ['view_audit']),
      ),
      location: Routes.audit,
    );
    expect(find.text('team.created'), findsOneWidget);
    // The navigation shows the audit log to those who may read it.
    expect(find.text(Messages.audit), findsWidgets);

    await tester.tap(find.text(Messages.olderEntries));
    await tester.pumpAndSettle();
    expect(find.text('team.deleted'), findsOneWidget);
    expect(find.text(Messages.olderEntries), findsNothing);
    expect(backend.sent('GET', '/audit').last.url.queryParameters, {
      'before': '9',
    });
  });

  testWidgets('others are refused by the server', (tester) async {
    final backend = FakeBackend()
      ..on('GET', '/audit', problem(403, 'forbidden'), status: 403)
      ..on('GET', '/organizations', organizationPage([]));
    await pumpApp(tester, await signedIn(backend), location: Routes.audit);
    expect(find.text('You are not allowed to do that.'), findsOneWidget);
    await tester.tap(find.text(Messages.organizations));
    await tester.pumpAndSettle();
    // And the navigation does not offer it.
    expect(find.text(Messages.audit), findsNothing);
  });
}
