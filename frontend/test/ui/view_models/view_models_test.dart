import 'dart:async';
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:kanbot/data/repositories/auth_repository.dart';
import 'package:kanbot/data/services/api_exception.dart';
import 'package:kanbot/domain/models/team.dart';
import 'package:kanbot/ui/core/loadable.dart';
import 'package:kanbot/ui/features/audit/audit_view_model.dart';
import 'package:kanbot/ui/features/organizations/organization_view_model.dart';
import 'package:kanbot/ui/features/organizations/organizations_view_model.dart';
import 'package:kanbot/ui/features/teams/team_view_model.dart';
import 'package:kanbot/ui/features/teams/teams_view_model.dart';
import 'package:kanbot/utils/result.dart';

import '../../helpers/fake_backend.dart';
import '../../helpers/test_dependencies.dart';

/// How a request fails: the error paths of frontend/AGENTS.md §7.
enum Breakage { unavailable, network, unauthorized, malformed }

/// Makes every `GET` of [paths] fail with [breakage].
void breakAll(FakeBackend backend, List<String> paths, Breakage breakage) {
  for (final path in paths) {
    backend.handle('GET', path, (_) {
      switch (breakage) {
        case Breakage.unavailable:
          return http.Response(
            '{"type":"about:blank","title":"x","status":503,"code":"unavailable"}',
            503,
            headers: {'content-type': 'application/problem+json'},
          );
        case Breakage.unauthorized:
          return http.Response(
            '{"type":"about:blank","title":"x","status":401,"code":"unauthorized"}',
            401,
            headers: {'content-type': 'application/problem+json'},
          );
        case Breakage.network:
          throw http.ClientException('connection refused');
        case Breakage.malformed:
          return http.Response(
            'not json',
            200,
            headers: {'content-type': 'application/json'},
          );
      }
    });
  }
}

/// Runs [load]. A `2xx` that breaks the contract is a bug, not an outcome
/// (frontend/AGENTS.md §5): it is thrown, for the error reporter. `true` if
/// the load completed, so its state can be checked.
Future<bool> loads(Future<void> Function() load, Breakage breakage) async {
  if (breakage == Breakage.malformed) {
    await expectLater(load(), throwsA(isA<FormatException>()));
    return false;
  }
  await load();
  return true;
}

Matcher failedWith(Breakage breakage) => isA<LoadFailed<Object?>>().having(
  (loadable) => loadable.error,
  'error',
  switch (breakage) {
    Breakage.unavailable => isA<ApiUnavailableException>(),
    Breakage.network => isA<ApiNetworkException>(),
    Breakage.unauthorized => isA<ApiUnauthorizedException>(),
    Breakage.malformed => isA<FormatException>(),
  },
);

void main() {
  for (final breakage in Breakage.values) {
    group('$breakage', () {
      test('organizations list', () async {
        final backend = FakeBackend();
        breakAll(backend, ['/organizations'], breakage);
        final dependencies = await signedIn(backend);
        final viewModel = OrganizationsViewModel(
          repository: dependencies.organizations,
        );
        if (await loads(viewModel.load, breakage)) {
          expect(viewModel.organizations, failedWith(breakage));
        }
        if (breakage == Breakage.unauthorized) {
          // A 401 ends the session (once the token it answered is known
          // to be the current one): the router then shows sign-in.
          await pumpEventQueue();
          expect(dependencies.auth.status, AuthStatus.signedOut);
        }
      });

      test('one organization', () async {
        final backend = FakeBackend()
          ..on('GET', '/organizations/$orgId', organization())
          ..on('GET', '/organizations/$orgId/admins', <Object?>[]);
        breakAll(backend, ['/organizations/$orgId/teams'], breakage);
        final dependencies = await signedIn(backend);
        final viewModel = OrganizationViewModel(
          id: orgId,
          organizations: dependencies.organizations,
          teams: dependencies.teams,
        );
        if (await loads(viewModel.load, breakage)) {
          expect(viewModel.details, failedWith(breakage));
        }
      });

      test('teams list and one team', () async {
        final backend = FakeBackend();
        breakAll(backend, [
          '/teams',
          '/teams/$teamId',
          '/teams/$teamId/members',
        ], breakage);
        final dependencies = await signedIn(backend);
        final teams = TeamsViewModel(repository: dependencies.teams);
        if (await loads(teams.load, breakage)) {
          expect(teams.teams, failedWith(breakage));
        }
        final team = TeamViewModel(id: teamId, teams: dependencies.teams);
        if (await loads(team.load, breakage)) {
          expect(team.details, failedWith(breakage));
        }
      });

      test('audit log', () async {
        final backend = FakeBackend();
        breakAll(backend, ['/audit'], breakage);
        final dependencies = await signedIn(backend);
        final viewModel = AuditViewModel(users: dependencies.users);
        if (await loads(viewModel.load, breakage)) {
          expect(viewModel.entries, failedWith(breakage));
          expect(viewModel.hasMore, isFalse);
        }
      });
    });
  }

  test('a ViewModel disposed while loading does not notify', () async {
    final backend = FakeBackend()
      ..on('GET', '/organizations', organizationPage([]));
    final dependencies = await signedIn(backend);
    final viewModel = OrganizationsViewModel(
      repository: dependencies.organizations,
    );
    final loading = viewModel.load();
    viewModel.dispose();
    await expectLater(loading, completes);
  });

  test('a reload that finishes last does not win over a newer one', () async {
    final first = Completer<void>();
    var calls = 0;
    final backend = FakeBackend()
      ..handle('GET', '/organizations/$orgId', (_) async {
        final name = ++calls == 1 ? 'Old' : 'New';
        if (name == 'Old') await first.future;
        return http.Response(
          jsonEncode(organization(name: name)),
          200,
          headers: {'content-type': 'application/json'},
        );
      })
      ..on('GET', '/organizations/$orgId/admins', <Object?>[])
      ..on('GET', '/organizations/$orgId/teams', <Object?>[]);
    final dependencies = await signedIn(backend);
    final viewModel = OrganizationViewModel(
      id: orgId,
      organizations: dependencies.organizations,
      teams: dependencies.teams,
    );

    final older = viewModel.load();
    await viewModel.load();
    first.complete();
    await older;

    expect(
      viewModel.details,
      isA<Loaded<OrganizationDetails>>().having(
        (details) => details.value.organization.name,
        'name',
        'New',
      ),
    );
  });

  test('a page of members that arrives after a reload is dropped', () async {
    final pageTwo = Completer<void>();
    var firstPages = 0;
    final backend = FakeBackend()
      ..on('GET', '/teams/$teamId', team())
      ..handle('GET', '/teams/$teamId/members', (request) async {
        final Map<String, Object?> page;
        if (request.url.queryParameters.containsKey('after')) {
          await pageTwo.future;
          page = memberPage([
            {
              'user': user(id: orgId, name: 'Carol'),
              'role': 'member',
              'source': 'manual',
            },
          ]);
        } else {
          // The reload sees Bob's new role.
          final role = ++firstPages == 1 ? 'member' : 'maintainer';
          page = memberPage([
            {'user': user(), 'role': role, 'source': 'manual'},
          ], next: 'cursor');
        }
        return http.Response(
          jsonEncode(page),
          200,
          headers: {'content-type': 'application/json'},
        );
      });
    final dependencies = await signedIn(backend);
    final viewModel = TeamViewModel(id: teamId, teams: dependencies.teams);
    await viewModel.load();

    final more = viewModel.loadMore();
    expect(viewModel.loadingMore, isTrue);
    await viewModel.load();
    pageTwo.complete();
    await more;

    expect(viewModel.loadingMore, isFalse);
    final details = viewModel.details;
    expect(details, isA<Loaded<TeamDetails>>());
    final members = (details as Loaded<TeamDetails>).value.members;
    expect(members.map((member) => member.role), [TeamRole.maintainer]);
  });

  test('a change keeps the ViewModel busy until it has reloaded', () async {
    final removed = Completer<void>();
    final backend = FakeBackend()
      ..on('GET', '/organizations/$orgId', organization())
      ..on('GET', '/organizations/$orgId/admins', [user()])
      ..on('GET', '/organizations/$orgId/teams', <Object?>[])
      ..handle('DELETE', '/organizations/$orgId/admins/$bobId', (_) async {
        await removed.future;
        return http.Response('', 204);
      });
    final dependencies = await signedIn(backend);
    final viewModel = OrganizationViewModel(
      id: orgId,
      organizations: dependencies.organizations,
      teams: dependencies.teams,
    );
    await viewModel.load();
    final bob =
        (viewModel.details as Loaded<OrganizationDetails>).value.admins.single;
    expect(viewModel.busy, isFalse);

    final removing = viewModel.removeAdmin(bob);
    expect(viewModel.busy, isTrue);
    removed.complete();
    expect(await removing, isA<Ok<void>>());

    expect(viewModel.busy, isFalse);
  });
}
