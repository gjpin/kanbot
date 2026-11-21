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
  factory AppDependencies.create({
    required bool web,
    required bool release,
    required TelemetryExporters telemetry,
    Uri? defaultServer,
  }) {
    final tokenStore = web ? null : TokenStore();
    ApiConnection newConnection() =>
        ApiConnection(newHttpClient: http.Client.new, tokenStore: tokenStore);
    final connection = newConnection();
    final auth = AuthRepository(
      connection: connection,
      web: web,
      tokenStore: tokenStore,
      webAuth: const FlutterWebAuth(),
      nativeRedirect: switch (defaultTargetPlatform) {
        TargetPlatform.windows ||
        TargetPlatform.linux => () => loopbackRedirect(freeLoopbackPort),
        _ => appSchemeRedirect,
      },
      navigate: browser.navigateTo,
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

  /// A connection of its own, to check a server before switching to it.
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

  /// Connects to the server (the page's origin on the web, the stored or
  /// default one natively), then loads the session in the background.
  /// Without a server, the router asks the user for one.
  Future<void> start({Uri? page}) async {
    final server = web && page != null
        ? webApiBaseUrl(page)
        : await serverStore?.read(release: release) ?? defaultServer;
    if (server == null) return;
    connection.connect(server);
    await auth.refresh();
  }
}
