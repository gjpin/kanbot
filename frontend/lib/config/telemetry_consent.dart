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
    // Each update runs after the previous one, whether it failed or not.
    pending = pending.then((_) => _apply(), onError: (_) => _apply());
  }

  bool get _allowed {
    final user = _auth.user;
    final server = _auth.server;
    return _auth.status == AuthStatus.signedIn &&
        user != null &&
        user.telemetryOptIn &&
        server != null &&
        server.telemetryAvailable &&
        _connection.baseUrl != null;
  }

  Future<void> _apply() async {
    try {
      final baseUrl = _connection.baseUrl;
      if (!_allowed || baseUrl == null) {
        await _exporters.disable();
        return;
      }
      final store = _tokenStore;
      final token = store == null ? null : await store.read(server: baseUrl);
      // Signed out meanwhile, or (natively) no session token to send it
      // with: nothing goes out.
      if (!_allowed || (store != null && token == null)) {
        await _exporters.disable();
        return;
      }
      await _exporters.enable(telemetryEndpoint(baseUrl), {
        'x-kanbot-csrf': '1',
        'authorization': ?(token == null ? null : 'Bearer $token'),
      });
    } on Object {
      // Secure storage or an exporter failed: send nothing rather than
      // risk sending without consent.
      try {
        await _exporters.disable();
      } on Object {
        // Nothing more to do.
      }
    }
  }

  void dispose() => _auth.removeListener(_update);
}
