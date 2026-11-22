import 'dart:convert';

import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:kanbot/routing/router.dart';
import 'package:kanbot/ui/core/messages.dart';
import 'package:kanbot/ui/features/teams/team_page.dart';
import 'package:kanbot/ui/features/teams/teams_page.dart';
import 'package:shad/shad.dart';

import '../helpers/fake_backend.dart';
import '../helpers/pump.dart';
import '../helpers/test_dependencies.dart';

void main() {
  FakeBackend backendFor({
    List<String> permissions = const [],
    String? idpGroup,
    List<Object?>? members,
  }) => FakeBackend()
    ..on(
      'GET',
      '/teams/$teamId',
      team(permissions: permissions, idpGroup: idpGroup),
    )
    ..on(
      'GET',
      '/teams/$teamId/members',
      memberPage(
        members ??
            [
              {'user': user(), 'role': 'maintainer', 'source': 'manual'},
            ],
      ),
    );

  testWidgets('teams list, with the create button for those allowed', (
    tester,
  ) async {
    final backend = FakeBackend()
      ..on('GET', '/teams', [teamSummary(idpGroup: 'platform-team')])
      ..on('GET', '/teams/$teamId', team())
      ..on('GET', '/teams/$teamId/members', memberPage([]));
    await pumpApp(
      tester,
      await signedIn(backend, user: me(permissions: ['create_team'])),
      location: Routes.teams,
    );
    expect(find.text(Messages.newTeam), findsOneWidget);
    expect(find.text(Messages.fromIdentityProvider), findsOneWidget);
    await tester.tap(find.text('Platform'));
    await tester.pumpAndSettle();
    expect(find.byType(TeamPage), findsOneWidget);
  });

  testWidgets('creating a team opens it', (tester) async {
    final backend = FakeBackend()
      ..on('GET', '/teams', <Object?>[])
      ..on('POST', '/teams', team(), status: 201)
      ..on('GET', '/teams/$teamId', team())
      ..on('GET', '/teams/$teamId/members', memberPage([]));
    await pumpApp(
      tester,
      await signedIn(backend, user: me(permissions: ['create_team'])),
      location: Routes.teams,
    );
    await tester.tap(find.text(Messages.newTeam));
    await tester.pumpAndSettle();
    final fields = find.descendant(
      of: find.byType(ShadDialog),
      matching: find.byType(EditableText),
    );
    await tester.enterText(fields.at(0), 'Platform');
    await tester.enterText(fields.at(1), 'platform');
    await tester.tap(find.text(Messages.create));
    await tester.pumpAndSettle();
    expect(find.byType(TeamPage), findsOneWidget);
  });

  testWidgets('members see the team, and no controls', (tester) async {
    await pumpApp(
      tester,
      await signedIn(backendFor()),
      location: Routes.team(teamId),
    );
    expect(find.text('Bob'), findsOneWidget);
    expect(find.text(Messages.maintainer), findsOneWidget);
    for (final control in [
      Messages.rename,
      Messages.deleteTeam,
      Messages.addMember,
      Messages.remove,
      Messages.idpGroup,
    ]) {
      expect(find.text(control), findsNothing, reason: control);
    }
  });

  testWidgets('maintainers add and remove members', (tester) async {
    final backend = backendFor(permissions: ['manage', 'manage_members'])
      ..on('GET', '/users', [user(id: orgId, name: 'Carol')])
      ..on('PUT', '/teams/$teamId/members/$orgId', null, status: 204)
      ..on('DELETE', '/teams/$teamId/members/$bobId', null, status: 204);
    await pumpApp(
      tester,
      await signedIn(backend),
      location: Routes.team(teamId),
    );

    await tester.tap(find.text(Messages.addMember));
    await tester.pumpAndSettle();
    await tester.enterText(
      find.descendant(
        of: find.byType(ShadDialog),
        matching: find.byType(EditableText),
      ),
      'car',
    );
    await tester.tap(find.byIcon(LucideIcons.search));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Carol'));
    await tester.pumpAndSettle();
    expect(
      jsonDecode(
        backend.sent('PUT', '/teams/$teamId/members/$orgId').single.body,
      ),
      {'role': 'member'},
    );

    await tester.tap(find.text(Messages.remove));
    await tester.pumpAndSettle();
    expect(
      backend.sent('DELETE', '/teams/$teamId/members/$bobId'),
      hasLength(1),
    );
  });

  testWidgets('long member lists load a page at a time', (tester) async {
    final backend = backendFor()
      ..handle('GET', '/teams/$teamId/members', (request) {
        final after = request.url.queryParameters['after'];
        final page = after == null
            ? memberPage([
                {'user': user(), 'role': 'maintainer', 'source': 'manual'},
              ], next: 'page-2')
            : memberPage([
                {
                  'user': user(id: orgId, name: 'Eve', disabled: true),
                  'role': 'member',
                  'source': 'manual',
                },
              ]);
        return http.Response(
          jsonEncode(page),
          200,
          headers: {'content-type': 'application/json'},
        );
      });
    await pumpApp(
      tester,
      await signedIn(backend),
      location: Routes.team(teamId),
    );
    expect(find.text('Bob'), findsOneWidget);
    expect(find.text('Eve'), findsNothing);

    await tester.tap(find.text(Messages.moreMembers));
    await tester.pumpAndSettle();
    expect(find.text('Bob'), findsOneWidget);
    expect(find.text('Eve'), findsOneWidget);
    // A disabled member is marked, so a maintainer can remove them.
    expect(find.text(Messages.disabledUser), findsOneWidget);
    expect(find.text(Messages.moreMembers), findsNothing, reason: 'last page');
    expect(
      backend
          .sent('GET', '/teams/$teamId/members')
          .last
          .url
          .queryParameters['after'],
      'page-2',
    );
  });

  testWidgets('identity provider members are read-only', (tester) async {
    await pumpApp(
      tester,
      await signedIn(
        backendFor(
          permissions: ['manage', 'set_idp_group'],
          idpGroup: 'platform-team',
          members: [
            {'user': user(), 'role': 'member', 'source': 'idp'},
          ],
        ),
      ),
      location: Routes.team(teamId),
    );
    expect(find.text(Messages.fromIdentityProvider), findsOneWidget);
    expect(find.text(Messages.remove), findsNothing);
    expect(find.text(Messages.addMember), findsNothing);
    expect(find.text(Messages.stopSyncing), findsOneWidget);
  });

  testWidgets('platform admins set and clear the group', (tester) async {
    final backend = backendFor(
      permissions: ['manage', 'manage_members', 'set_idp_group'],
    )..on('PATCH', '/teams/$teamId', team(idpGroup: 'platform-team'));
    await pumpApp(
      tester,
      await signedIn(backend),
      location: Routes.team(teamId),
    );

    backend.on(
      'GET',
      '/teams/$teamId',
      team(permissions: ['manage', 'set_idp_group'], idpGroup: 'platform-team'),
    );
    await tester.enterText(find.byType(EditableText).first, ' platform-team ');
    await tester.tap(find.text(Messages.save));
    await tester.pumpAndSettle();
    expect(jsonDecode(backend.sent('PATCH', '/teams/$teamId').single.body), {
      'idp_group': 'platform-team',
    });
    expect(find.text(Messages.saved), findsOneWidget);

    backend
      ..on('DELETE', '/teams/$teamId/idp_group', team())
      ..on(
        'GET',
        '/teams/$teamId',
        team(permissions: ['manage', 'set_idp_group']),
      );
    await tester.tap(find.text(Messages.stopSyncing));
    await tester.pumpAndSettle();
    expect(backend.sent('DELETE', '/teams/$teamId/idp_group'), hasLength(1));
  });

  testWidgets('maintainers delete the team after confirming', (tester) async {
    final backend = backendFor(permissions: ['manage'])
      ..on('DELETE', '/teams/$teamId', null, status: 204)
      ..on('GET', '/teams', <Object?>[]);
    await pumpApp(
      tester,
      await signedIn(backend),
      location: Routes.team(teamId),
    );
    await tester.tap(find.text(Messages.deleteTeam));
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(ShadButton, Messages.delete));
    await tester.pumpAndSettle();
    expect(backend.sent('DELETE', '/teams/$teamId'), hasLength(1));
    expect(find.byType(TeamsPage), findsOneWidget);
  });
}
