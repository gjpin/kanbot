import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_web_plugins/url_strategy.dart';
import 'package:go_router/go_router.dart';
import 'package:kanbot/config/api_config.dart';
import 'package:kanbot/config/dependencies.dart';
import 'package:kanbot/config/telemetry.dart';
import 'package:kanbot/data/services/browser.dart' as browser;
import 'package:kanbot/routing/router.dart';
import 'package:kanbot/ui/core/messages.dart';
import 'package:kanbot/ui/core/theme.dart';
import 'package:shad/shad.dart';

Future<void> main() async {
  // The web app's routes are the page's path (`/login?error=...` from the
  // server's sign-in redirect), not a `#` fragment. Set before anything
  // starts the app, as Flutter requires; a no-op elsewhere.
  usePathUrlStrategy();
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
  if (kIsWeb) dependencies.connectWeb(browser.currentPage());
  // Started before the first frame, so a native app shows the loading page,
  // not the server page, while it reads the stored server. Failures end on
  // the login page, which says what went wrong; an error that is a bug
  // (AGENTS.md §5) also reaches reportUncaughtErrors.
  final started = dependencies.start(
    page: kIsWeb ? browser.currentPage() : null,
  );
  final router = createRouter(dependencies: dependencies);
  reportNavigation(router);
  runApp(KanbotApp(router: router));
  unawaited(started);
}

class KanbotApp extends StatelessWidget {
  const KanbotApp({super.key, required this.router});

  final GoRouter router;

  @override
  Widget build(BuildContext context) {
    return ShadApp.router(
      title: Messages.appName,
      theme: AppTheme.light,
      darkTheme: AppTheme.dark,
      themeMode: ShadThemeMode.system,
      routerConfig: router,
    );
  }
}
