import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import 'package:kanbot/config/api_config.dart';
import 'package:kanbot/config/telemetry.dart';
import 'package:kanbot/config/telemetry_consent.dart';
import 'package:kanbot/data/repositories/auth_repository.dart';
import 'package:kanbot/data/repositories/organizations_repository.dart';
import 'package:kanbot/data/repositories/teams_repository.dart';
import 'package:kanbot/data/repositories/users_repository.dart';
import 'package:kanbot/data/services/api_connection.dart';
import 'package:kanbot/data/services/browser.dart' as browser;
import 'package:kanbot/data/services/loopback.dart';
import 'package:kanbot/data/services/server_store.dart';
import 'package:kanbot/data/services/token_store.dart';
import 'package:kanbot/data/services/web_auth.dart';
import 'package:kanbot/ui/core/messages.dart';

/// The app's long-lived services, created once in `main` and handed to the
/// router, which passes them through constructors to the pages and
/// ViewModels that need them.
class AppDependencies {
  AppDependencies({
    required this.web,
    required this.release,
    required this.connection,
    required this.auth,
    required this.newConnection,
    this.serverStore,
    this.defaultServer,
  }) : organizations = OrganizationsRepository(connection: connection),
       teams = TeamsRepository(connection: connection),
       users = UsersRepository(connection: connection);

  /// The production services. Native apps keep their session token and
  /// server in secure storage; the web app keeps nothing.
  ///
  /// The rest are the app's connections to the outside world, which tests
  /// replace: the HTTP client, the browser sign-in, page navigation (web)
  /// and the free loopback port (Windows, Linux). Everything else is wired
  /// here, for tests as for the app.
  factory AppDependencies.create({
    required bool web,
    required bool release,
    required TelemetryExporters telemetry,
    Uri? defaultServer,
    http.Client Function() newHttpClient = http.Client.new,
    WebAuth? webAuth,
    void Function(Uri url) navigate = browser.navigateTo,
    Future<int> Function() freePort = freeLoopbackPort,
  }) {
    final tokenStore = web ? null : TokenStore();
    final connection = ApiConnection(
      newHttpClient: newHttpClient,
      tokenStore: tokenStore,
    );
    // Checking another server never carries the current session token.
    ApiConnection newConnection() =>
        ApiConnection(newHttpClient: newHttpClient);
    final auth = AuthRepository(
      connection: connection,
      web: web,
      tokenStore: tokenStore,
      webAuth:
          webAuth ??
          FlutterWebAuth(
            landingPageHtml: landingPage(
              title: Messages.appName,
              message: Messages.signInLanding,
            ),
          ),
      nativeRedirect: switch (defaultTargetPlatform) {
        TargetPlatform.windows ||
        TargetPlatform.linux => () => loopbackRedirect(freePort),
        _ => appSchemeRedirect,
      },
      navigate: navigate,
    );
    TelemetryConsent(
      auth: auth,
      connection: connection,
      exporters: telemetry,
      tokenStore: tokenStore,
    );
    return AppDependencies(
      web: web,
      release: release,
      connection: connection,
      auth: auth,
      newConnection: newConnection,
      serverStore: web ? null : ServerStore(),
      defaultServer: defaultServer,
    );
  }

  /// Whether this is the web app (same-origin server, cookie session).
  final bool web;

  /// Whether this is a release build (server URLs must be https and not
  /// loopback).
  final bool release;

  /// The current server.
  final ApiConnection connection;

  /// A connection of its own, without the session token, to check a
  /// server before switching to it.
  final ApiConnection Function() newConnection;

  /// The session.
  final AuthRepository auth;

  /// Native apps: the chosen server.
  final ServerStore? serverStore;

  /// Native apps: the build's default server (`API_BASE_URL`), if any.
  final Uri? defaultServer;

  final OrganizationsRepository organizations;
  final TeamsRepository teams;
  final UsersRepository users;

  final ValueNotifier<bool> _starting = ValueNotifier(false);

  /// Whether [start] is still looking for the native app's server. The
  /// router shows the loading page meanwhile, not the server page.
  ValueListenable<bool> get starting => _starting;

  /// Connects to the server (the page's origin on the web, the stored or
  /// default one natively), then loads the session. Without a server, the
  /// router asks the user for one.
  ///
  /// Call it before `runApp`: [starting] is set at once, so the first frame
  /// shows the loading page. A server the user chooses meanwhile wins over
  /// the stored one.
  Future<void> start({Uri? page}) async {
    if (web && page != null) {
      connectWeb(page);
    } else if (!await _restoreServer()) {
      return;
    }
    await auth.refresh();
  }

  /// Connects to the stored server, else the default one. Whether it did:
  /// not without a server, nor when the user chose one meanwhile.
  Future<bool> _restoreServer() async {
    var chosen = false;
    void choose() => chosen = true;
    connection.addListener(choose);
    _starting.value = true;
    try {
      Uri? stored;
      try {
        stored = await serverStore?.read(release: release);
      } on Exception {
        // Secure storage failed: ask for the server again.
      }
      final server = stored ?? defaultServer;
      if (chosen || server == null) return false;
      connection.connect(server);
      return true;
    } finally {
      connection.removeListener(choose);
      // Connected first, so the router never sees "no server, not
      // starting" on the way.
      _starting.value = false;
    }
  }

  /// The web app: connects to the origin of [page] at once, so the first
  /// frame already knows its server (it never asks for one). Call before
  /// `runApp`.
  void connectWeb(Uri page) {
    if (!connection.isConnected) connection.connect(webApiBaseUrl(page));
  }
}
