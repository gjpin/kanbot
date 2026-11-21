import 'package:kanbot/config/telemetry.dart';
import 'package:kanbot/data/repositories/auth_repository.dart';
import 'package:kanbot/data/services/api_connection.dart';
import 'package:kanbot/data/services/token_store.dart';

/// Sends telemetry only while a user is signed in who opted in, to a
/// server that relays it (AGENTS.md §3a). Follows [AuthRepository]: export
/// starts after sign-in or opt-in, and stops on sign-out or opt-out.
class TelemetryConsent {
  TelemetryConsent({
    required this._auth,
    required this._connection,
    required this._exporters,
    this._tokenStore,
  }) {
    _auth.addListener(_update);
  }

  final AuthRepository _auth;
  final ApiConnection _connection;
  final TelemetryExporters _exporters;

  /// Native apps: the session token the exports carry. The web app has
  /// none; its exports carry the session cookie.
  final TokenStore? _tokenStore;

  /// The last update, so tests and callers can wait for it.
  Future<void> pending = Future.value();

  void _update() {
    pending = pending.then((_) => _apply());
  }

  Future<void> _apply() async {
    final user = _auth.user;
    final server = _auth.server;
    final baseUrl = _connection.baseUrl;
    final allowed =
        _auth.status == AuthStatus.signedIn &&
        user != null &&
        user.telemetryOptIn &&
        server != null &&
        server.telemetryAvailable &&
        baseUrl != null;
    if (!allowed) {
      await _exporters.disable();
      return;
    }
    final store = _tokenStore;
    final token = store == null ? null : await store.read();
    await _exporters.enable(telemetryEndpoint(baseUrl), {
      'x-kanbot-csrf': '1',
      'authorization': ?(token == null ? null : 'Bearer $token'),
    });
  }

  void dispose() => _auth.removeListener(_update);
}
