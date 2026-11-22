import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:kanbot/routing/router.dart';

import '../helpers/fake_backend.dart';
import '../helpers/pump.dart';
import '../helpers/test_dependencies.dart';

/// The key screens, as images (frontend/AGENTS.md §7). Update them only for
/// an intended visual change: `flutter test --update-goldens test/ui/goldens_test.dart`,
/// and say so in the commit message.
void main() {
  Future<void> golden(WidgetTester tester, String name) => expectLater(
    find.byType(Directionality).first,
    matchesGoldenFile('goldens/$name.png'),
  );

  testWidgets('sign-in', (tester) async {
    final backend = FakeBackend()
      ..on('GET', '/auth/config', authConfig())
      ..on('GET', '/me', problem(401, 'unauthorized'), status: 401);
    final dependencies = testDependencies(backend: backend);
    await dependencies.auth.refresh();
    await pumpApp(tester, dependencies, location: Routes.login);
    await golden(tester, 'sign_in');
  });

  testWidgets('organizations', (tester) async {
    final backend = FakeBackend()
      ..on(
        'GET',
        '/organizations',
        organizationPage([
          {'id': orgId, 'slug': 'acme', 'name': 'Acme'},
          {'id': teamId, 'slug': 'globex', 'name': 'Globex'},
        ]),
      );
    await pumpApp(
      tester,
      await signedIn(
        backend,
        user: me(role: 'admin', permissions: ['create_organization']),
      ),
    );
    await golden(tester, 'organizations');
  });

  testWidgets('organization', (tester) async {
    final backend = FakeBackend()
      ..on(
        'GET',
        '/organizations/$orgId',
        organization(
          permissions: ['manage', 'manage_admins', 'manage_team_links'],
        ),
      )
      ..on('GET', '/organizations/$orgId/admins', [
        user(),
        user(id: teamId, name: 'Eve', disabled: true),
      ])
      ..on('GET', '/organizations/$orgId/teams', [
        {
          'team': {'id': teamId, 'slug': 'platform', 'name': 'Platform'},
          'access': 'write',
        },
      ]);
    await pumpApp(
      tester,
      await signedIn(backend),
      location: Routes.organization(orgId),
    );
    await golden(tester, 'organization');
  });

  testWidgets('team', (tester) async {
    final backend = FakeBackend()
      ..on(
        'GET',
        '/teams/$teamId',
        team(permissions: ['manage', 'manage_members']),
      )
      ..on(
        'GET',
        '/teams/$teamId/members',
        memberPage([
          {'user': user(), 'role': 'maintainer', 'source': 'manual'},
          {
            'user': user(id: orgId, name: 'Dave'),
            'role': 'member',
            'source': 'idp',
          },
        ], next: 'more'),
      );
    await pumpApp(
      tester,
      await signedIn(backend),
      location: Routes.team(teamId),
    );
    await golden(tester, 'team');
  });
}
