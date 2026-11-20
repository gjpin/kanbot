import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:go_router/go_router.dart';
import 'package:kanbot/config/api_config.dart';
import 'package:kanbot/config/dependencies.dart';
import 'package:kanbot/config/telemetry.dart';
import 'package:kanbot/routing/router.dart';
import 'package:kanbot/ui/core/theme.dart';
import 'package:shad/shad.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  // Throws on a misconfigured build (for example a release without
  // API_BASE_URL), so it fails at startup rather than on the first request.
  final apiBaseUrl = apiBaseUrlFromEnvironment(release: kReleaseMode);
  await initTelemetry(apiBaseUrl: apiBaseUrl);
  reportUncaughtErrors();
  final router = createRouter(
    dependencies: AppDependencies.create(apiBaseUrl: apiBaseUrl),
  );
  reportNavigation(router);
  runApp(KanbotApp(router: router));
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
