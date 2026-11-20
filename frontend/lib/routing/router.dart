import 'package:go_router/go_router.dart';
import 'package:kanbot/config/dependencies.dart';
import 'package:kanbot/ui/core/not_found_page.dart';
import 'package:kanbot/ui/features/home/views/home_page.dart';

/// Route paths. Use these instead of string literals.
abstract final class Routes {
  static const String home = '/';
}

/// Builds the app's router. Create it once (in `main`), never in `build()`.
///
/// Route builders take the services their pages need from [dependencies]
/// and pass them through constructors.
///
/// Unknown paths, including deep links, show [NotFoundPage]. Protected routes
/// get a `redirect` that checks auth state once auth exists (AGENTS.md §2).
GoRouter createRouter({
  required AppDependencies dependencies,
  String initialLocation = Routes.home,
}) => GoRouter(
  initialLocation: initialLocation,
  routes: [
    GoRoute(path: Routes.home, builder: (context, state) => const HomePage()),
  ],
  errorBuilder: (context, state) => const NotFoundPage(),
);
