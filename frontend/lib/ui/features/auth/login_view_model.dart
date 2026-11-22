import 'package:kanbot/data/repositories/auth_repository.dart';
import 'package:kanbot/data/services/api_connection.dart';
import 'package:kanbot/data/services/server_store.dart';
import 'package:kanbot/ui/core/view_model.dart';
import 'package:kanbot/utils/result.dart';

/// Signing in, and (natively) going back to choose another server.
class LoginViewModel extends ViewModel {
  LoginViewModel({
    required this._auth,
    required this._connection,
    this._serverStore,
    String? error,
  }) : _error = error == null ? null : SignInRefusedException(error) {
    _auth.addListener(notifyListeners);
  }

  final AuthRepository _auth;
  final ApiConnection _connection;
  final ServerStore? _serverStore;

  bool _busy = false;

  /// This page's own error: a failed sign-in, or the server's redirect.
  Exception? _error;

  bool get busy => _busy;

  /// Why the last sign-in failed (from this page, or from the server's
  /// redirect, `/login?error=...` on the web), else why the session could
  /// not be loaded from the current server.
  Exception? get error => _error ?? _auth.lastError;

  /// The server's address, shown so the user knows where they sign in.
  Uri? get server => _connection.baseUrl;

  /// Shows the server's `error` from a failed web sign-in.
  void showServerError(String? error) {
    if (error == null) return;
    _error = SignInRefusedException(error);
    notifyListeners();
  }

  /// Native apps can change server; the web app belongs to its server.
  bool get canChangeServer => _serverStore != null;

  Future<void> signIn() => _run(_auth.signIn);

  /// Tries to load the session again (the server was unreachable).
  Future<void> retry() => _run(_auth.refresh);

  /// Runs [action], showing its failure. Anything it throws that is not an
  /// [Exception] is a bug (AGENTS.md §5): it propagates to be reported, and
  /// the repository's error says what happened.
  Future<void> _run(Future<Result<void>> Function() action) async {
    if (_busy) return;
    _busy = true;
    _error = null;
    notifyListeners();
    try {
      final result = await action();
      if (result case Failure(:final error)) _error = error;
    } on Exception catch (error) {
      _error = error;
    } finally {
      _busy = false;
      notifyListeners();
    }
  }

  /// Forgets the server and its session token; the router shows the
  /// server page.
  Future<void> changeServer() async {
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
