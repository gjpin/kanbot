import 'package:flutter_test/flutter_test.dart';
import 'package:kanbot/main.dart';
import 'package:kanbot/routing/router.dart';
import 'package:shad/shad.dart';

import 'helpers/test_dependencies.dart';

void main() {
  testWidgets('counter increments', (tester) async {
    await tester.pumpWidget(
      KanbotApp(router: createRouter(dependencies: testDependencies())),
    );

    expect(find.text('0'), findsOneWidget);
    expect(find.text('1'), findsNothing);

    await tester.tap(find.byIcon(LucideIcons.plus));
    await tester.pump();

    expect(find.text('0'), findsNothing);
    expect(find.text('1'), findsOneWidget);
  });
}
