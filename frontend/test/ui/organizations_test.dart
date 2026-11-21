import 'dart:convert';

import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:kanbot/routing/router.dart';
import 'package:kanbot/ui/core/messages.dart';
import 'package:kanbot/ui/features/organizations/organization_page.dart';
import 'package:kanbot/ui/features/organizations/organizations_page.dart';
import 'package:shad/shad.dart';

import '../helpers/fake_backend.dart';
import '../helpers/pump.dart';
import '../helpers/test_dependencies.dart';

void main() {
  group('organizations list', () {
    testWidgets('lists organizations and opens one', (tester) async {
      final backend = FakeBackend()
        ..on('GET', '/organizations', [
          {'id': orgId, 'slug': 'acme', 'name': 'Acme'},
        ])
        ..on('GET', '/organizations/$orgId', organization())
        ..on('GET', '/organizations/$orgId/admins', <Object?>[])
        ..on('GET', '/organizations/$orgId/teams', <Object?>[]);
      await pumpApp(tester, await signedIn(backend));

      expect(find.text(Messages.newOrganization), findsNothing);
      await tester.tap(find.text('Acme'));
      await tester.pumpAndSettle();
      expect(find.byType(OrganizationPage), findsOneWidget);
    });

    testWidgets('a failure offers a retry', (tester) async {
      final backend = FakeBackend()
        ..on('GET', '/organizations', problem(503, 'unavailable'), status: 503);
      await pumpApp(tester, await signedIn(backend));
      expect(find.text(Messages.retry), findsOneWidget);

      backend.on('GET', '/organizations', <Object?>[]);
      await tester.tap(find.text(Messages.retry));
      await tester.pumpAndSettle();
      expect(find.text(Messages.nothingHere), findsOneWidget);
    });

    testWidgets('platform admins create organizations', (tester) async {
      final backend = FakeBackend()
        ..on('GET', '/organizations', <Object?>[])
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
        );
      final dependencies = await signedIn(
        backend,
        user: me(role: 'admin', permissions: ['create_organization']),
      );
      await pumpApp(tester, dependencies);

      await tester.tap(find.text(Messages.newOrganization));
      await tester.pumpAndSettle();
      final fields = find.descendant(
        of: find.byType(ShadDialog),
        matching: find.byType(EditableText),
      );
      await tester.enterText(fields.at(0), 'Acme');
      await tester.enterText(fields.at(1), 'Acme!');
      await tester.tap(find.text(Messages.create));
      await tester.pumpAndSettle();

      // The server's field error shows next to the slug.
      expect(find.text(Messages.fieldError('invalid')), findsOneWidget);
      expect(jsonDecode(backend.sent('POST', '/organizations').single.body), {
        'slug': 'Acme!',
        'name': 'Acme',
      });

      backend
        ..on('POST', '/organizations', organization(), status: 201)
        ..on('GET', '/organizations/$orgId', organization())
        ..on('GET', '/organizations/$orgId/admins', <Object?>[])
        ..on('GET', '/organizations/$orgId/teams', <Object?>[]);
      await tester.enterText(fields.at(1), 'acme');
      await tester.tap(find.text(Messages.create));
      await tester.pumpAndSettle();
      expect(find.byType(OrganizationPage), findsOneWidget);
    });
  });

  group('organization page', () {
    FakeBackend backendFor({List<String> permissions = const []}) =>
        FakeBackend()
          ..on(
            'GET',
            '/organizations/$orgId',
            organization(permissions: permissions),
          )
          ..on('GET', '/organizations/$orgId/admins', [user()])
          ..on('GET', '/organizations/$orgId/teams', [
            {'team': teamSummary(), 'access': 'write'},
          ]);

    testWidgets('readers see the organization, and no controls', (
      tester,
    ) async {
      await pumpApp(
        tester,
        await signedIn(backendFor()),
        location: Routes.organization(orgId),
      );
      expect(find.text('Acme'), findsWidgets);
      expect(find.text('Bob'), findsOneWidget);
      expect(find.text('Platform'), findsOneWidget);
      expect(find.text(Messages.write), findsOneWidget);
      for (final control in [
        Messages.rename,
        Messages.deleteOrganization,
        Messages.addAdmin,
        Messages.linkTeam,
        Messages.remove,
      ]) {
        expect(find.text(control), findsNothing, reason: control);
      }
    });

    testWidgets('admins add an admin found by name', (tester) async {
      final backend = backendFor(permissions: ['manage_admins'])
        ..on('GET', '/users', [user(id: teamId, name: 'Carol')])
        ..on('PUT', '/organizations/$orgId/admins/$teamId', null, status: 204);
      await pumpApp(
        tester,
        await signedIn(backend),
        location: Routes.organization(orgId),
      );

      await tester.tap(find.text(Messages.addAdmin));
      await tester.pumpAndSettle();
      await tester.enterText(
        find.descendant(
          of: find.byType(ShadDialog),
          matching: find.byType(EditableText),
        ),
        'car',
      );
      await tester.testTextInput.receiveAction(TextInputAction.done);
      await tester.pumpAndSettle();
      await tester.tap(find.text('Carol'));
      await tester.pumpAndSettle();

      expect(backend.sent('GET', '/users').single.url.queryParameters, {
        'query': 'car',
      });
      expect(
        backend.sent('PUT', '/organizations/$orgId/admins/$teamId'),
        hasLength(1),
      );
      // Reloaded after the change.
      expect(backend.sent('GET', '/organizations/$orgId/admins'), hasLength(2));
    });

    testWidgets('admins remove an admin; failures are shown', (tester) async {
      final backend = backendFor(permissions: ['manage_admins'])
        ..on(
          'DELETE',
          '/organizations/$orgId/admins/$bobId',
          problem(403, 'forbidden'),
          status: 403,
        );
      await pumpApp(
        tester,
        await signedIn(backend),
        location: Routes.organization(orgId),
      );

      await tester.tap(find.text(Messages.remove));
      await tester.pumpAndSettle();

      expect(find.text('You are not allowed to do that.'), findsOneWidget);
      expect(backend.sent('GET', '/organizations/$orgId/admins'), hasLength(1));
    });

    testWidgets('admins unlink a team', (tester) async {
      final backend = backendFor(
        permissions: ['manage_team_links'],
      )..on('DELETE', '/organizations/$orgId/teams/$teamId', null, status: 204);
      await pumpApp(
        tester,
        await signedIn(backend),
        location: Routes.organization(orgId),
      );
      expect(find.byType(AccessSelect), findsOneWidget);

      backend.on('GET', '/organizations/$orgId/teams', <Object?>[]);
      await tester.tap(find.text(Messages.remove));
      await tester.pumpAndSettle();

      expect(
        backend.sent('DELETE', '/organizations/$orgId/teams/$teamId'),
        hasLength(1),
      );
      expect(find.text('Platform'), findsNothing);
    });

    testWidgets('platform admins delete it after confirming', (tester) async {
      final backend = backendFor(permissions: ['delete'])
        ..on('DELETE', '/organizations/$orgId', null, status: 204)
        ..on('GET', '/organizations', <Object?>[]);
      await pumpApp(
        tester,
        await signedIn(backend),
        location: Routes.organization(orgId),
      );

      await tester.tap(find.text(Messages.deleteOrganization));
      await tester.pumpAndSettle();
      await tester.tap(find.text(Messages.cancel));
      await tester.pumpAndSettle();
      expect(backend.sent('DELETE', '/organizations/$orgId'), isEmpty);

      await tester.tap(find.text(Messages.deleteOrganization));
      await tester.pumpAndSettle();
      await tester.tap(find.widgetWithText(ShadButton, Messages.delete));
      await tester.pumpAndSettle();
      expect(backend.sent('DELETE', '/organizations/$orgId'), hasLength(1));
      expect(find.byType(OrganizationsPage), findsOneWidget);
    });
  });
}
