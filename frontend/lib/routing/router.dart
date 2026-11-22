import 'package:flutter/foundation.dart';
import 'package:go_router/go_router.dart';
import 'package:kanbot/config/dependencies.dart';
import 'package:kanbot/data/repositories/auth_repository.dart';
import 'package:kanbot/ui/core/not_found_page.dart';
import 'package:kanbot/ui/features/audit/audit_page.dart';
import 'package:kanbot/ui/features/auth/loading_page.dart';
import 'package:kanbot/ui/features/auth/login_page.dart';
import 'package:kanbot/ui/features/auth/server_page.dart';
import 'package:kanbot/ui/features/organizations/organization_page.dart';
import 'package:kanbot/ui/features/organizations/organizations_page.dart';
import 'package:kanbot/ui/features/settings/settings_page.dart';
import 'package:kanbot/ui/features/teams/team_page.dart';
import 'package:kanbot/ui/features/teams/teams_page.dart';

/// Route paths. Use these instead of string literals.
abstract final class Routes {
  static const String home = '/';
  static const String server = '/server';
  static const String login = '/login';
  static const String loading = '/loading';
  static const String teams = '/teams';
  static const String audit = '/audit';
  static const String settings = '/settings';

  static String organization(String id) => '/organizations/$id';
  static String team(String id) => '/teams/$id';

  /// Routes anyone may see, signed in or not.
  static const Set<String> public = {server, login, loading};
}

/// IDs in routes are UUIDs. Anything else is an invalid deep link.
final RegExp _uuid = RegExp(
  r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
);

/// Builds the app's router. Create it once (in `main`), never in `build()`.
///
/// Route builders take the services their pages need from [dependencies]
/// and pass them through constructors. Unknown paths, including deep links,
/// show [NotFoundPage], and so do invalid IDs.
///
/// Every route except [Routes.public] needs a signed-in user: [redirect]
/// sends everyone else to the server page (a native app without a server),
/// the loading page (while the session loads) or the login page.
GoRouter createRouter({
  required AppDependencies dependencies,
  String initialLocation = Routes.home,
}) {
  // IDs in links may come in upper case: the API's are lower case.
  String? id(GoRouterState state) {
    final raw = state.pathParameters['id']?.toLowerCase();
    return raw != null && _uuid.hasMatch(raw) ? raw : null;
  }

  return GoRouter(
    initialLocation: initialLocation,
    refreshListenable: Listenable.merge([
      dependencies.connection,
      dependencies.auth,
      dependencies.starting,
    ]),
    redirect: (context, state) => redirect(
      location: state.uri,
      starting: dependencies.starting.value,
      connected: dependencies.connection.isConnected,
      status: dependencies.auth.status,
    ),
    routes: [
      GoRoute(
        path: Routes.server,
        builder: (context, state) => ServerPage(dependencies: dependencies),
      ),
      GoRoute(
        path: Routes.login,
        builder: (context, state) => LoginPage(
          dependencies: dependencies,
          error: state.uri.queryParameters['error'],
        ),
      ),
      GoRoute(
        path: Routes.loading,
        builder: (context, state) => const LoadingPage(),
      ),
      GoRoute(
        path: Routes.home,
        builder: (context, state) =>
            OrganizationsPage(dependencies: dependencies),
      ),
      GoRoute(
        path: '/organizations/:id',
        builder: (context, state) => switch (id(state)) {
          // Keyed by ID: another organization is another page, with its
          // own ViewModel and data.
          final id? => OrganizationPage(
            key: ValueKey(id),
            dependencies: dependencies,
            id: id,
          ),
          null => const NotFoundPage(),
        },
      ),
      GoRoute(
        path: Routes.teams,
        builder: (context, state) => TeamsPage(dependencies: dependencies),
      ),
      GoRoute(
        path: '/teams/:id',
        builder: (context, state) => switch (id(state)) {
          final id? => TeamPage(
            key: ValueKey(id),
            dependencies: dependencies,
            id: id,
          ),
          null => const NotFoundPage(),
        },
      ),
      GoRoute(
        path: Routes.audit,
        builder: (context, state) => AuditPage(dependencies: dependencies),
      ),
      GoRoute(
        path: Routes.settings,
        builder: (context, state) => SettingsPage(dependencies: dependencies),
      ),
    ],
    errorBuilder: (context, state) => const NotFoundPage(),
  );
}

/// Where a request for [location] goes, or `null` to show it.
///
/// - Looking for the stored server ([starting], native), or session
///   loading: the loading page, remembering [location] in `from`.
/// - No server (native): the server page.
/// - Signed out: the login page; everything else goes there.
/// - Signed in: the pages before sign-in go home (or back to `from`).
@visibleForTesting
String? redirect({
  required Uri location,
  required bool starting,
  required bool connected,
  required AuthStatus status,
}) {
  final path = location.path;
  if ((!connected && starting) || (connected && status == AuthStatus.unknown)) {
    if (path == Routes.loading) return null;
    return Uri(
      path: Routes.loading,
      queryParameters: {'from': location.toString()},
    ).toString();
  }
  if (!connected) return path == Routes.server ? null : Routes.server;
  if (path == Routes.loading) {
    final from = _internal(location.queryParameters['from']);
    return redirect(
          location: Uri.parse(from),
          starting: starting,
          connected: connected,
          status: status,
        ) ??
        from;
  }
  // Connected: the server page has done its job.
  final public = Routes.public.contains(path) && path != Routes.server;
  return switch (status) {
    AuthStatus.signedOut => public ? null : Routes.login,
    _ => public || path == Routes.server ? Routes.home : null,
  };
}

/// [raw] if it is a path inside the app, else home: `from` must not lead
/// elsewhere.
String _internal(String? raw) {
  final uri = raw == null ? null : Uri.tryParse(raw);
  if (uri == null ||
      uri.hasScheme ||
      uri.hasAuthority ||
      !uri.path.startsWith('/') ||
      uri.path.startsWith('//') ||
      uri.path.contains(r'\') ||
      // Never back to the loading page: it would loop.
      uri.path == Routes.loading) {
    return Routes.home;
  }
  return uri.toString();
}
