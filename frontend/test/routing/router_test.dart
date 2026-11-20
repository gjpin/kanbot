import 'package:flutter_test/flutter_test.dart';
import 'package:kanbot/main.dart';
import 'package:kanbot/routing/router.dart';
import 'package:kanbot/ui/core/not_found_page.dart';
import 'package:kanbot/ui/features/home/views/home_page.dart';

import '../helpers/test_dependencies.dart';

void main() {
  testWidgets('starts on the home page', (tester) async {
    await tester.pumpWidget(
      KanbotApp(router: createRouter(dependencies: testDependencies())),
    );

    expect(find.byType(HomePage), findsOneWidget);
    expect(find.byType(NotFoundPage), findsNothing);
  });

  testWidgets('unknown path shows the not-found page', (tester) async {
    await tester.pumpWidget(
      KanbotApp(
        router: createRouter(
          dependencies: testDependencies(),
          initialLocation: '/no/such/page',
        ),
      ),
    );

    expect(find.byType(NotFoundPage), findsOneWidget);
    expect(find.byType(HomePage), findsNothing);
  });

  testWidgets('not-found page leads back home', (tester) async {
    await tester.pumpWidget(
      KanbotApp(
        router: createRouter(
          dependencies: testDependencies(),
          initialLocation: '/no/such/page',
        ),
      ),
    );

    await tester.tap(find.text('Go home'));
    await tester.pumpAndSettle();

    expect(find.byType(HomePage), findsOneWidget);
    expect(find.byType(NotFoundPage), findsNothing);
  });
}
