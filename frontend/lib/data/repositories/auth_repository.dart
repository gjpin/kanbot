import 'dart:io' show IOException;

import 'package:flutter/foundation.dart';
import 'package:kanbot/config/api_config.dart';
import 'package:kanbot/config/app_id.dart';
import 'package:kanbot/data/api/generated/kanbot_api.dart' as api;
import 'package:kanbot/data/repositories/api_result.dart';
import 'package:kanbot/data/repositories/mappers.dart';
import 'package:kanbot/data/services/api_connection.dart';
import 'package:kanbot/data/services/api_exception.dart';
import 'package:kanbot/data/services/pkce.dart';
import 'package:kanbot/data/services/token_store.dart';
import 'package:kanbot/data/services/web_auth.dart';
import 'package:kanbot/domain/models/server.dart';
import 'package:kanbot/domain/models/user.dart';
import 'package:kanbot/utils/result.dart';

/// Where the session stands.
enum AuthStatus {
  /// Not known yet: the app is asking the server.
  unknown,
  signedOut,
  signedIn,
}

/// The server refused the sign-in. [code] is the backend's `error`
/// (`access_denied`, `login_failed`, `no_role`, or one this app version
/// does not know).
final class SignInRefusedException implements Exception {
  const SignInRefusedException(this.code);

  final String code;
}

/// The server did not answer like a kanbot server (a page that is not its
/// API, a sign-in page on another site).
final class NotKanbotServerException implements Exception {
  const NotKanbotServerException();
}

/// Loading the session ended with an error that is not an outcome: most
/// likely a response that breaks the API contract (a `TypeError` from the
/// generated client, AGENTS.md §5). That error itself propagates, to be
/// reported as uncaught; this one is what the login page shows meanwhile.
final class UnexpectedResponseException implements Exception {
  const UnexpectedResponseException();
}

/// How a platform receives the end of a native sign-in.
typedef NativeRedirect = ({String redirectUri, String callback});

/// The session: who is signed in, at which server, and signing in and
/// out. The router listens to it (protected routes, AGENTS.md §2).
///
/// - **Web:** the session is the backend's `HttpOnly` cookie. Signing in
///   and out are full-page navigations to the server; the app stores
///   nothing.
/// - **Native:** the app opens the server's sign-in page in the system
///   browser, receives a one-time code and redeems it with its PKCE
///   verifier for a session token, kept in [TokenStore].
class AuthRepository extends ChangeNotifier {
  AuthRepository({
    required this._connection,
    required this._web,
    this._tokenStore,
    required this._webAuth,
    required this._nativeRedirect,
    required this._navigate,
  }) {
    _connection.onUnauthorized = _sessionEnded;
  }

  final ApiConnection _connection;
  final bool _web;
  final TokenStore? _tokenStore;
  final WebAuth _webAuth;

  /// Where this platform receives the native sign-in.
  final Future<NativeRedirect> Function() _nativeRedirect;

  /// A full-page navigation (web only).
  final void Function(Uri url) _navigate;

  AuthStatus _status = AuthStatus.unknown;
  User? _user;
  ServerInfo? _server;
  Exception? _lastError;

  /// Numbers native sign-ins: a newer one, or a server change, replaces
  /// the one before it.
  int _signIns = 0;

  /// The native sign-in waiting for the browser, if any.
  int? _inBrowser;

  AuthStatus get status => _status;

  /// Whether a native sign-in waits for the browser. Signing in again
  /// then replaces it: the user may have closed the browser, which the
  /// app does not learn on Windows and Linux until the sign-in times out.
  bool get waitingForBrowser => _inBrowser != null;

  /// The signed-in user, while [status] is [AuthStatus.signedIn].
  User? get user => _user;

  /// The server's sign-in settings, once loaded.
  ServerInfo? get server => _server;

  /// Why the last [refresh] could not load the session (the server is
  /// down, for example); `null` after one that could.
  Exception? get lastError => _lastError;

  /// Asks the current server what it is (`GET /auth/config`).
  Future<Result<ServerInfo>> checkServer() async {
    final result = await _call(
      () async => serverInfoFrom(await _connection.api.auth.config()),
    );
    if (result case Ok(:final value)) _server = value;
    return result;
  }

  /// Loads the session from the server: signed in when `GET /me` works,
  /// signed out on `401`. Other failures (the server is down) leave the
  /// user signed out with the error, so the login page can say so.
  ///
  /// A response that breaks the API contract throws (AGENTS.md §5), and
  /// still leaves the user signed out, with [UnexpectedResponseException].
  Future<Result<void>> refresh() => _signedOutUnlessCompleted(_refresh);

  Future<Result<void>> _refresh() async {
    final server = await checkServer();
    if (server case Failure(:final error)) {
      _lastError = error;
      _setSignedOut();
      return Failure(error);
    }
    final me = await _call(_connection.api.users.me);
    switch (me) {
      case Ok(:final value):
        _lastError = null;
        _user = userFrom(value);
        _status = AuthStatus.signedIn;
        notifyListeners();
        return const Ok(null);
      case Failure(error: ApiUnauthorizedException()):
        _lastError = null;
        await _forgetToken();
        _setSignedOut();
        return const Ok(null);
      case Failure(:final error):
        _lastError = error;
        _setSignedOut();
        return Failure(error);
    }
  }

  /// Signs in. On the web this navigates away to the server; natively it
  /// completes once the session token is stored.
  ///
  /// Failures: [SignInCancelledException], [SignInFailedException],
  /// [SignInRefusedException], [NotKanbotServerException], or an
  /// [ApiException]. A response that breaks the API contract throws, as in
  /// [refresh].
  Future<Result<void>> signIn() => _signedOutUnlessCompleted(_signIn);

  Future<Result<void>> _signIn() async {
    var server = _server;
    if (server == null) {
      switch (await checkServer()) {
        case Ok(:final value):
          server = value;
        case Failure(:final error):
          return Failure(error);
      }
    }
    // The server says where to sign in: only ever a page of its own.
    final baseUrl = _connection.baseUrl;
    if (baseUrl == null || !isBelow(server.loginUrl, baseUrl)) {
      return const Failure(NotKanbotServerException());
    }
    if (_web) {
      _navigate(server.loginUrl.replace(queryParameters: {'platform': 'web'}));
      return const Ok(null);
    }
    return _signInNative(server.loginUrl, baseUrl);
  }

  Future<Result<void>> _signInNative(Uri loginUrl, Uri baseUrl) async {
    final pkce = Pkce.generate();
    final attempt = ++_signIns;
    final NativeRedirect redirect;
    final Uri result;
    try {
      // Windows and Linux: a free loopback port, which can fail.
      redirect = await _nativeRedirect();
      _setInBrowser(attempt);
      result = await _webAuth.authenticate(
        url: loginUrl.replace(
          queryParameters: {
            'platform': 'native',
            'redirect_uri': redirect.redirectUri,
            'code_challenge': pkce.challenge,
            'code_challenge_method': 'S256',
          },
        ),
        callback: redirect.callback,
      );
    } on SignInCancelledException catch (error) {
      return Failure(error);
    } on SignInFailedException catch (error) {
      return Failure(error);
    } on IOException {
      return const Failure(SignInFailedException());
    } finally {
      if (_inBrowser == attempt) _setInBrowser(null);
    }
    // Replaced meanwhile: its code is not redeemed.
    if (attempt != _signIns) return const Failure(SignInCancelledException());
    final expected = Uri.parse(redirect.redirectUri);
    final code = result.queryParameters['code'];
    final ours =
        result.scheme == expected.scheme &&
        result.host == expected.host &&
        result.port == expected.port &&
        result.path == expected.path;
    if (!ours || code == null || code.isEmpty) {
      return Failure(
        SignInRefusedException(result.queryParameters['error'] ?? 'unknown'),
      );
    }
    final token = await _call(
      () => _connection.api.auth.token(
        body: api.TokenRequest(code: code, codeVerifier: pkce.verifier),
      ),
    );
    switch (token) {
      case Failure(:final error):
        return Failure(error);
      case Ok(:final value):
        try {
          await _tokenStore?.write(value.sessionToken, server: baseUrl);
        } on Exception catch (_) {
          return const Failure(SignInFailedException());
        }
        return refresh();
    }
  }

  /// Signs out at the server, forgets the session, and on the web sends
  /// the browser to the identity provider's sign-out page when the server
  /// returns one. A server that cannot be reached, or answers something
  /// else, still signs the user out here.
  Future<void> signOut() async {
    final Result<api.LogoutResponse> result;
    try {
      result = await _call(_connection.api.auth.logout);
    } finally {
      // Even when the answer breaks the contract (and that error goes on
      // to be reported): the session must end here.
      await _forgetToken();
      _setSignedOut();
    }
    if (result case Ok(:final value) when _web) {
      final logoutUrl = Uri.tryParse(value.logoutUrl ?? '');
      if (logoutUrl != null && isLogoutUrl(logoutUrl)) _navigate(logoutUrl);
    }
  }

  /// Sets whether the app may send telemetry (`PUT /me/preferences`).
  Future<Result<void>> setTelemetryOptIn({required bool optIn}) async {
    final result = await _call(
      () => _connection.api.users.updatePreferences(
        body: api.Preferences(telemetryOptIn: optIn),
      ),
    );
    switch (result) {
      case Ok(:final value):
        _user = userFrom(value);
        notifyListeners();
        return const Ok(null);
      case Failure(:final error):
        return Failure(error);
    }
  }

  /// Runs an API [call] like [apiResult]. A response that is not JSON at
  /// all, or a sign-in URL that is not a URL, is
  /// [NotKanbotServerException]: something other than a kanbot server
  /// answered (an HTML page served for every path, for example). A JSON
  /// response that breaks the contract still throws (AGENTS.md §5).
  static Future<Result<T>> _call<T>(Future<T> Function() call) async {
    try {
      return await apiResult(call);
    } on FormatException {
      return const Failure(NotKanbotServerException());
    }
  }

  /// Runs [body]. When it throws instead of completing (a response that
  /// breaks the contract, AGENTS.md §5), the error propagates to be
  /// reported, but the user is left signed out with
  /// [UnexpectedResponseException] rather than loading forever.
  Future<T> _signedOutUnlessCompleted<T>(Future<T> Function() body) async {
    var completed = false;
    try {
      final result = await body();
      completed = true;
      return result;
    } finally {
      if (!completed) {
        _lastError = const UnexpectedResponseException();
        _setSignedOut();
      }
    }
  }

  /// Clears the stored token. Secure storage failing changes nothing for
  /// the user: the token cannot be read either, and is replaced at the next
  /// sign-in.
  Future<void> _forgetToken() async {
    try {
      await _tokenStore?.clear();
    } on Exception {
      // See above.
    }
  }

  /// The server answered `401` to a request that carried [token]: that
  /// session is gone. A late answer to a request of an earlier session
  /// (the user signed in again meanwhile) leaves the current one alone.
  void _sessionEnded(String? token) {
    if (_status != AuthStatus.signedIn) return;
    final store = _tokenStore;
    final baseUrl = _connection.baseUrl;
    if (store == null || token == null || baseUrl == null) {
      _endSession();
      return;
    }
    store.read(server: baseUrl).then((current) {
      if (current == token && _status == AuthStatus.signedIn) {
        _endSession();
      }
    }, onError: (Object _) => _endSession()).ignore();
  }

  void _endSession() {
    // Best effort: the token is useless now; a failed delete only leaves a
    // dead token, refused again on the next start.
    _tokenStore?.clear().ignore();
    _setSignedOut();
  }

  void _setInBrowser(int? attempt) {
    _inBrowser = attempt;
    notifyListeners();
  }

  void _setSignedOut() {
    _user = null;
    _status = AuthStatus.signedOut;
    notifyListeners();
  }

  /// Forgets the server's settings and its session token (a native user
  /// changes server): the token must never reach another server. The last
  /// error was the old server's, so it goes too.
  Future<void> forgetServer() async {
    _server = null;
    _lastError = null;
    // A sign-in still in the browser was for the old server.
    _signIns++;
    _inBrowser = null;
    await _forgetToken();
    _setSignedOut();
  }
}

/// Whether [url] is a page of the server at [baseUrl]: same scheme, host
/// and port, below its path, without credentials.
bool isBelow(Uri url, Uri baseUrl) =>
    url.scheme == baseUrl.scheme &&
    url.host == baseUrl.host &&
    url.port == baseUrl.port &&
    url.userInfo.isEmpty &&
    url.path.startsWith(baseUrl.path);

/// Whether [url] may be the identity provider's logout page: `https` (or
/// `http` on a loopback host ([isLoopbackHost]), for development), with a
/// host and no credentials. Anything else (`javascript:`, a relative URL)
/// is ignored.
bool isLogoutUrl(Uri url) {
  final loopback = isLoopbackHost(url.host);
  return (url.scheme == 'https' || (url.scheme == 'http' && loopback)) &&
      url.host.isNotEmpty &&
      url.userInfo.isEmpty;
}

/// The native redirect on Android, iOS and macOS: the app's scheme.
Future<NativeRedirect> appSchemeRedirect() async =>
    (redirectUri: appRedirectUri, callback: applicationId);

/// The native redirect on Windows and Linux: a loopback URL on a free port
/// from [freePort].
Future<NativeRedirect> loopbackRedirect(Future<int> Function() freePort) async {
  final port = await freePort();
  return (
    redirectUri: 'http://127.0.0.1:$port/auth/done',
    callback: 'http://127.0.0.1:$port',
  );
}
