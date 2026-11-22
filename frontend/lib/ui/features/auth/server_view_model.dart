import 'dart:convert';

import 'package:kanbot/config/api_config.dart';
import 'package:kanbot/data/repositories/api_result.dart';
import 'package:kanbot/data/repositories/auth_repository.dart';
import 'package:kanbot/data/services/api_connection.dart';
import 'package:kanbot/data/services/api_exception.dart';
import 'package:kanbot/data/services/server_store.dart';
import 'package:kanbot/ui/core/view_model.dart';
import 'package:kanbot/utils/result.dart';

/// Choosing the kanbot server (native apps).
class ServerViewModel extends ViewModel {
  ServerViewModel({
    required this._connection,
    required this._newConnection,
    required this._auth,
    this._store,
    required this._release,
  });

  final ApiConnection _connection;
  final ApiConnection Function() _newConnection;
  final AuthRepository _auth;

  /// Native apps only; the web app never chooses a server.
  final ServerStore? _store;
  final bool _release;

  bool _busy = false;
  Exception? _error;

  /// A check is running.
  bool get busy => _busy;

  /// Why the last attempt failed.
  Exception? get error => _error;

  /// Checks that [raw] is a kanbot server (`GET /auth/config`), then
  /// remembers it and switches to it. The router then moves on to sign-in.
  Future<void> connect(String raw) async {
    if (_busy) return;
    final Uri server;
    try {
      server = parseApiBaseUrl(raw.trim(), release: _release);
    } on FormatException catch (error) {
      _set(busy: false, error: error);
      return;
    }
    _set(busy: true, error: null);
    final probe = _newConnection()..connect(server);
    final Result<void> checked;
    try {
      checked = await _probe(probe);
    } finally {
      probe.dispose();
    }
    switch (checked) {
      case Failure(:final error):
        _set(busy: false, error: error);
      case Ok():
        try {
          await _store?.write(server);
        } on Exception {
          // Secure storage failed: connect anyway; the server is asked
          // for again on the next start.
        }
        _connection.connect(server);
        _set(busy: false, error: null);
        await _auth.refresh();
    }
  }

  /// `GET /auth/config` on [probe]. A server that answers, but not like
  /// kanbot (another site's page or JSON, a `404`), is
  /// [NotKanbotServerException].
  static Future<Result<void>> _probe(ApiConnection probe) async {
    final answered = await apiResult(() => probe.getUndecoded('auth/config'));
    return switch (answered) {
      Ok(:final value) when _isAuthConfig(value.body) => const Ok(null),
      Ok() || Failure(error: ApiNotFoundException()) => const Failure(
        NotKanbotServerException(),
      ),
      Failure(:final error) => Failure(error),
    };
  }

  /// Whether [body] is what kanbot answers to `GET /auth/config`.
  static bool _isAuthConfig(String body) {
    final Object? json;
    try {
      json = jsonDecode(body);
    } on FormatException {
      return false;
    }
    return switch (json) {
      {
        'login_url': String _,
        'telemetry_available': bool _,
        'version': String _,
      } =>
        true,
      _ => false,
    };
  }

  void _set({required bool busy, required Exception? error}) {
    _busy = busy;
    _error = error;
    notifyListeners();
  }
}
