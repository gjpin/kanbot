import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:go_router/go_router.dart';
import 'package:kanbot/config/api_config.dart';
import 'package:kanbot/config/dependencies.dart';
import 'package:kanbot/config/telemetry.dart';
import 'package:kanbot/data/services/browser.dart' as browser;
import 'package:kanbot/routing/router.dart';
import 'package:kanbot/ui/core/theme.dart';
import 'package:shad/shad.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  // Throws on a misconfigured build (an invalid API_BASE_URL), so it fails
  // at startup rather than on the first request.
  final defaultServer = defaultServerUrl(release: kReleaseMode);
  final telemetry = TelemetryExporters();
  await initTelemetry(telemetry);
  reportUncaughtErrors();
  final dependencies = AppDependencies.create(
    web: kIsWeb,
    release: kReleaseMode,
    telemetry: telemetry,
    defaultServer: defaultServer,
  );
  final router = createRouter(dependencies: dependencies);
  reportNavigation(router);
  runApp(KanbotApp(router: router));
  // The router shows the loading page meanwhile; failures end on the
  // login page, which says what went wrong.
  unawaited(dependencies.start(page: kIsWeb ? browser.currentPage() : null));
}

class KanbotApp extends StatelessWidget {
  const KanbotApp({super.key, required this.router});

  final GoRouter router;

  @override
  Widget build(BuildContext context) {
    return ShadApp.router(
      title: 'Kanbot',
      theme: AppTheme.light,
      darkTheme: AppTheme.dark,
      themeMode: ShadThemeMode.system,
      routerConfig: router,
    );
  }
}
