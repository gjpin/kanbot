import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:kanbot/data/services/api_exception.dart';
import 'package:kanbot/domain/models/organization.dart';
import 'package:kanbot/domain/models/team.dart';
import 'package:kanbot/utils/result.dart';

import '../../helpers/fake_backend.dart';
import '../../helpers/test_dependencies.dart';

/// The value of an [Ok], failing the test otherwise.
T ok<T>(Result<T> result) => switch (result) {
  Ok(:final value) => value,
  Failure(:final error) => fail('expected success, got $error'),
};

/// The error of a [Failure], failing the test otherwise.
Exception failure<T>(Result<T> result) => switch (result) {
  Failure(:final error) => error,
  Ok() => fail('expected a failure'),
};

Object? body(http.Request request) => jsonDecode(request.body);

void main() {
  late FakeBackend backend;

  setUp(() => backend = FakeBackend());

  group('organizations', () {
    test('lists and reads, with permissions', () async {
      backend
        ..on('GET', '/organizations', [
          {'id': orgId, 'slug': 'acme', 'name': 'Acme'},
        ])
        ..on(
          'GET',
          '/organizations/$orgId',
          organization(
            permissions: [
              'write',
              'manage_team_links',
              'link_openshell_workspace',
              'new_one',
            ],
            openShellWorkspace: 'research',
          ),
        );
      final repository = testDependencies(backend: backend).organizations;

      expect(ok(await repository.list()).single.name, 'Acme');
      final read = ok(await repository.get(orgId));
      expect(read.permissions, {
        OrganizationPermission.write,
        OrganizationPermission.manageTeamLinks,
        OrganizationPermission.linkOpenShellWorkspace,
      });
      expect(read.can(OrganizationPermission.delete), isFalse);
      expect(read.openShellWorkspace, 'research');
    });

    test('creates, updates and deletes', () async {
      backend
        ..on('POST', '/organizations', organization(), status: 201)
        ..on('PATCH', '/organizations/$orgId', organization(name: 'ACME'))
        ..on('DELETE', '/organizations/$orgId', null, status: 204);
      final repository = testDependencies(backend: backend).organizations;

      ok(await repository.create(slug: 'acme', name: 'Acme'));
      expect(body(backend.sent('POST', '/organizations').single), {
        'slug': 'acme',
        'name': 'Acme',
      });
      expect(ok(await repository.update(orgId, name: 'ACME')).name, 'ACME');
      expect(body(backend.sent('PATCH', '/organizations/$orgId').single), {
        'name': 'ACME',
      });
      ok(await repository.delete(orgId));
    });

    test('admins and team links', () async {
      backend
        ..on('GET', '/organizations/$orgId/admins', [
          user(),
          user(id: orgId, name: 'Eve', disabled: true),
        ])
        ..on('PUT', '/organizations/$orgId/admins/$bobId', null, status: 204)
        ..on('DELETE', '/organizations/$orgId/admins/$bobId', null, status: 204)
        ..on('GET', '/organizations/$orgId/teams', [
          {
            'team': {'id': teamId, 'slug': 'platform', 'name': 'Platform'},
            'access': 'write',
          },
          {
            'team': {'id': teamId, 'slug': 'platform', 'name': 'Platform'},
            'access': 'owner',
          },
        ])
        ..on('PUT', '/organizations/$orgId/teams/$teamId', null, status: 204)
        ..on(
          'DELETE',
          '/organizations/$orgId/teams/$teamId',
          null,
          status: 204,
        );
      final repository = testDependencies(backend: backend).organizations;

      final admins = ok(await repository.admins(orgId));
      expect(admins.map((admin) => (admin.displayName, admin.disabled)), [
        ('Bob', false),
        ('Eve', true),
      ]);
      ok(await repository.addAdmin(orgId, bobId));
      ok(await repository.removeAdmin(orgId, bobId));
      final links = ok(await repository.teamLinks(orgId));
      expect(links.first.access, Access.write);
      // Organization readers do not learn a linked team's group.
      expect(links.first.team.idpGroup, isNull);
      expect(links.first.team.name, 'Platform');
      // An access this app version does not know reads as the lowest.
      expect(links.last.access, Access.read);
      ok(await repository.linkTeam(orgId, teamId, Access.write));
      expect(
        body(backend.sent('PUT', '/organizations/$orgId/teams/$teamId').single),
        {'access': 'write'},
      );
      ok(await repository.unlinkTeam(orgId, teamId));
    });

    test('failures are typed', () async {
      backend
        ..on(
          'GET',
          '/organizations/$orgId',
          problem(404, 'not_found'),
          status: 404,
        )
        ..on(
          'POST',
          '/organizations',
          problem(
            422,
            'validation_failed',
            errors: [
              {'pointer': '/slug', 'code': 'invalid'},
            ],
          ),
          status: 422,
        )
        ..on(
          'DELETE',
          '/organizations/$orgId',
          problem(409, 'conflict'),
          status: 409,
        )
        ..handle(
          'GET',
          '/organizations',
          (_) => throw http.ClientException('down'),
        );
      final repository = testDependencies(backend: backend).organizations;

      expect(failure(await repository.get(orgId)), isA<ApiNotFoundException>());
      final invalid = failure(await repository.create(slug: '-', name: 'x'));
      expect(
        invalid,
        isA<ApiValidationException>().having(
          (e) => e.fieldErrors.single.pointer,
          'pointer',
          '/slug',
        ),
      );
      expect(
        failure(await repository.delete(orgId)),
        isA<ApiConflictException>(),
      );
      expect(failure(await repository.list()), isA<ApiNetworkException>());
    });
  });

  group('teams', () {
    test('reads teams and members', () async {
      backend
        ..on('GET', '/teams', [teamSummary(idpGroup: 'platform-team')])
        ..on(
          'GET',
          '/teams/$teamId',
          team(permissions: ['manage', 'manage_members', 'set_idp_group']),
        )
        ..on(
          'GET',
          '/teams/$teamId/members',
          memberPage([
            {'user': user(), 'role': 'maintainer', 'source': 'manual'},
            {'user': user(name: null), 'role': 'owner', 'source': 'scim'},
          ], next: 'cursor'),
        );
      final repository = testDependencies(backend: backend).teams;

      expect(ok(await repository.list()).single.idpGroup, 'platform-team');
      expect(ok(await repository.get(teamId)).permissions, {
        TeamPermission.manage,
        TeamPermission.manageMembers,
        TeamPermission.setIdpGroup,
      });
      final page = ok(await repository.members(teamId));
      expect(page.next, 'cursor');
      final members = page.members;
      expect(members.first.role, TeamRole.maintainer);
      expect(members.first.source, MembershipSource.manual);
      // Unknown values read as the least: a member, from the identity
      // provider (read-only).
      expect(members.last.role, TeamRole.member);
      expect(members.last.source, MembershipSource.idp);
      expect(members.last.user.displayName, isNull);
    });

    test('changes teams and members', () async {
      backend
        ..on('POST', '/teams', team(), status: 201)
        ..on('PATCH', '/teams/$teamId', team(idpGroup: 'g'))
        ..on('DELETE', '/teams/$teamId/idp_group', team())
        ..on('DELETE', '/teams/$teamId', null, status: 204)
        ..on('PUT', '/teams/$teamId/members/$bobId', null, status: 204)
        ..on('DELETE', '/teams/$teamId/members/$bobId', null, status: 204);
      final repository = testDependencies(backend: backend).teams;

      ok(await repository.create(slug: 'platform', name: 'Platform'));
      expect(ok(await repository.update(teamId, idpGroup: 'g')).idpGroup, 'g');
      expect(body(backend.sent('PATCH', '/teams/$teamId').single), {
        'idp_group': 'g',
      });
      expect(ok(await repository.clearIdpGroup(teamId)).idpGroup, isNull);
      ok(await repository.setMember(teamId, bobId, TeamRole.maintainer));
      expect(
        body(backend.sent('PUT', '/teams/$teamId/members/$bobId').single),
        {'role': 'maintainer'},
      );
      ok(await repository.removeMember(teamId, bobId));
      ok(await repository.delete(teamId));
    });
  });

  group('users', () {
    test('searches users and reads the audit log', () async {
      backend
        ..on('GET', '/users', [user()])
        ..handle('GET', '/audit', (request) {
          final before = request.url.queryParameters['before'];
          return http.Response(
            jsonEncode({
              'entries': [
                {
                  'id': before == null ? 9 : 3,
                  'at': '2026-11-21T10:00:00.000000Z',
                  'actor': user(),
                  'action': 'team.created',
                  'target_type': 'team',
                  'target_id': teamId,
                  'policy_ids': ['builtin.platform-admins'],
                  'details': <String, Object?>{},
                },
              ],
              'next_before': before == null ? 9 : null,
            }),
            200,
            headers: {'content-type': 'application/json'},
          );
        });
      final repository = testDependencies(backend: backend).users;

      expect(ok(await repository.search('bo')).single.id, bobId);
      expect(backend.sent('GET', '/users').single.url.queryParameters, {
        'query': 'bo',
      });
      final first = ok(await repository.audit());
      expect(first.entries.single.action, 'team.created');
      expect(first.entries.single.at, DateTime.utc(2026, 11, 21, 10));
      expect(first.nextBefore, 9);
      final second = ok(await repository.audit(before: 9));
      expect(second.entries.single.id, 3);
      expect(second.nextBefore, isNull);
    });
  });
}
