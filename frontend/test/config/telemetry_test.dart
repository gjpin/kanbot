import 'package:dartastic_opentelemetry/dartastic_opentelemetry.dart';
import 'package:dartastic_opentelemetry/testing.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:kanbot/config/telemetry.dart';
import 'package:kanbot/main.dart';
import 'package:kanbot/routing/router.dart';

import '../helpers/test_dependencies.dart';

void main() {
  late TestHarness harness;

  setUpAll(() async {
    harness = await maybeInitializeOtelForTest(serviceName: telemetryScope);
  });

  setUp(() => harness.clear());

  test('telemetry goes to the relay below the API base URL', () {
    expect(
      telemetryEndpoint(Uri.parse('https://api.example.com/v1/')),
      Uri.parse('https://api.example.com/v1/telemetry'),
    );
    expect(
      telemetryEndpoint(Uri.parse('http://localhost:3000/')),
      Uri.parse('http://localhost:3000/telemetry'),
    );
  });

  test('reports errors by type and stack, never their message', () {
    final stack = StackTrace.current;

    reportError(const FormatException('secret@example.com'), stack);

    final log = harness.logs.records.single;
    expect(log.severityNumber, Severity.ERROR);
    expect(log.eventName, 'exception');
    expect(log.attributes?.getString('exception.type'), 'FormatException');
    expect(log.attributes?.getString('exception.stacktrace'), stack.toString());
    expect(
      '${log.body} ${log.attributes?.toList()}',
      isNot(contains('secret')),
    );
  });

  test('reports errors without a stack', () {
    reportError(StateError('x'), null);

    final log = harness.logs.records.single;
    expect(log.attributes?.getString('exception.type'), 'StateError');
    expect(log.attributes?.getString('exception.stacktrace'), isNull);
  });

  test('reports uncaught framework errors and keeps presenting them', () {
    final previousFlutter = FlutterError.onError;
    final previousPlatform = PlatformDispatcher.instance.onError;
    addTearDown(() {
      FlutterError.onError = previousFlutter;
      PlatformDispatcher.instance.onError = previousPlatform;
    });
    final presented = <FlutterErrorDetails>[];
    FlutterError.onError = presented.add;

    reportUncaughtErrors();
    final details = FlutterErrorDetails(exception: StateError('boom'));
    FlutterError.onError!(details);

    expect(presented, [details]);
    expect(
      harness.logs.records.single.attributes?.getString('exception.type'),
      'StateError',
    );
  });

  test('reports uncaught platform errors without handling them', () {
    final previousFlutter = FlutterError.onError;
    final previousPlatform = PlatformDispatcher.instance.onError;
    addTearDown(() {
      FlutterError.onError = previousFlutter;
      PlatformDispatcher.instance.onError = previousPlatform;
    });

    reportUncaughtErrors();
    final handled = PlatformDispatcher.instance.onError!(
      ArgumentError('x'),
      StackTrace.current,
    );

    expect(handled, isFalse);
    expect(
      harness.logs.records.single.attributes?.getString('exception.type'),
      'ArgumentError',
    );
  });

  testWidgets('reports navigation by route template, not path', (tester) async {
    final router = createRouter(
      dependencies: testDependencies(),
      initialLocation: '/no/such/page',
    );
    reportNavigation(router);
    await tester.pumpWidget(KanbotApp(router: router));
    router.go(Routes.home);
    await tester.pumpAndSettle();

    final routes = [
      for (final log in harness.logs.records)
        if (log.eventName == 'app.navigation')
          log.attributes?.getString('app.route'),
    ];
    expect(routes, ['(unmatched)', '/']);
    expect(
      harness.logs.records.map((log) => '${log.attributes?.toList()}'),
      everyElement(isNot(contains('/no/such/page'))),
    );
  });
}
