import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:kanbot/config/dependencies.dart';
import 'package:kanbot/main.dart';
import 'package:kanbot/routing/router.dart';

/// Shows the app at [location] and lets it settle.
Future<void> pumpApp(
  WidgetTester tester,
  AppDependencies dependencies, {
  String location = Routes.home,
}) async {
  tester.view.physicalSize = const Size(1200, 1600);
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.reset);
  await tester.pumpWidget(
    KanbotApp(
      router: createRouter(
        dependencies: dependencies,
        initialLocation: location,
      ),
    ),
  );
  await tester.pumpAndSettle();
}
