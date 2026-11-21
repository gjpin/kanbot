import 'package:flutter/foundation.dart';
import 'package:kanbot/data/repositories/auth_repository.dart';
import 'package:kanbot/data/services/api_connection.dart';
import 'package:kanbot/data/services/server_store.dart';
import 'package:kanbot/utils/result.dart';

/// Signing in, and (natively) going back to choose another server.
class LoginViewModel extends ChangeNotifier {
  LoginViewModel({
    required this._auth,
    required this._connection,
    this._serverStore,
    String? error,
  }) {
    _error = error == null ? _auth.lastError : SignInRefusedException(error);
  }

  final AuthRepository _auth;
  final ApiConnection _connection;
  final ServerStore? _serverStore;

  bool _busy = false;
  Exception? _error;

  bool get busy => _busy;

  /// Why the last sign-in failed: from this page, or from the server's
  /// redirect (`/login?error=...`, web).
  Exception? get error => _error;

  /// The server's address, shown so the user knows where they sign in.
  Uri? get server => _connection.baseUrl;

  /// Native apps can change server; the web app belongs to its server.
  bool get canChangeServer => _serverStore != null;

  Future<void> signIn() async {
    _busy = true;
    _error = null;
    notifyListeners();
    final result = await _auth.signIn();
    _busy = false;
    if (result case Failure(:final error)) _error = error;
    notifyListeners();
  }

  /// Forgets the server; the router shows the server page.
  Future<void> changeServer() async {
    await _serverStore?.clear();
    _auth.forgetServer();
    _connection.disconnect();
  }

  /// Tries to load the session again (the server was unreachable).
  Future<void> retry() async {
    _busy = true;
    _error = null;
    notifyListeners();
    final result = await _auth.refresh();
    _busy = false;
    if (result case Failure(:final error)) _error = error;
    notifyListeners();
  }
}
