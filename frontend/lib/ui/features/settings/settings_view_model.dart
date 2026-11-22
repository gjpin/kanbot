import 'package:kanbot/data/repositories/auth_repository.dart';
import 'package:kanbot/data/services/api_connection.dart';
import 'package:kanbot/data/services/server_store.dart';
import 'package:kanbot/domain/models/server.dart';
import 'package:kanbot/domain/models/user.dart';
import 'package:kanbot/ui/core/view_model.dart';
import 'package:kanbot/utils/result.dart';

/// The user's settings: telemetry consent, signing out, the server.
class SettingsViewModel extends ViewModel {
  SettingsViewModel({
    required this._auth,
    required this._connection,
    this._serverStore,
  }) {
    _auth.addListener(notifyListeners);
  }

  final AuthRepository _auth;
  final ApiConnection _connection;
  final ServerStore? _serverStore;

  bool _busy = false;
  Exception? _error;

  User? get user => _auth.user;
  ServerInfo? get server => _auth.server;
  Uri? get serverUrl => _connection.baseUrl;
  bool get busy => _busy;
  Exception? get error => _error;

  /// Native apps can change server; the web app belongs to its server.
  bool get canChangeServer => _serverStore != null;

  Future<void> setTelemetryOptIn({required bool optIn}) async {
    _busy = true;
    _error = null;
    notifyListeners();
    final result = await _auth.setTelemetryOptIn(optIn: optIn);
    _busy = false;
    if (result case Failure(:final error)) _error = error;
    notifyListeners();
  }

  bool _leaving = false;

  /// Signs out. A second tap while it runs does nothing.
  Future<void> signOut() async {
    if (_leaving) return;
    _leaving = true;
    try {
      await _auth.signOut();
    } finally {
      _leaving = false;
    }
  }

  /// Signs out and forgets the server; the router shows the server page.
  Future<void> changeServer() async {
    if (_leaving) return;
    _leaving = true;
    try {
      await _changeServer();
    } finally {
      _leaving = false;
    }
  }

  Future<void> _changeServer() async {
    await _auth.signOut();
    try {
      await _serverStore?.clear();
    } on Exception {
      // Secure storage failed: the server comes back on the next start.
    }
    await _auth.forgetServer();
    _connection.disconnect();
  }

  @override
  void dispose() {
    _auth.removeListener(notifyListeners);
    super.dispose();
  }
}
