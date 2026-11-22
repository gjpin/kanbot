import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import 'package:kanbot/data/api/generated/kanbot_api.dart';
import 'package:kanbot/data/services/api_client.dart';
import 'package:kanbot/data/services/token_store.dart';

/// The kanbot server the app talks to, and the generated client for it.
///
/// The web app connects once, to the origin it was loaded from. A native
/// app connects to the server the user chose (`ServerStore`), and again
/// whenever they choose another one. Repositories read [api] at call time,
/// so they always reach the current server.
class ApiConnection extends ChangeNotifier {
  ApiConnection({
    required this._newHttpClient,
    this._tokenStore,
    this.onUnauthorized,
  });

  final http.Client Function() _newHttpClient;
  final TokenStore? _tokenStore;

  /// Called when the server answers `401`, with the token the request
  /// carried (see [ApiClient.onUnauthorized]).
  void Function(String? token)? onUnauthorized;

  ApiClient? _client;
  KanbotApi? _api;

  /// The server's API base URL, or `null` before one is chosen.
  Uri? get baseUrl => _client?.baseUrl;

  bool get isConnected => _api != null;

  /// The generated client for the current server.
  ///
  /// Throws a [StateError] before [connect]: the router never shows a page
  /// that needs the API until a server is chosen.
  KanbotApi get api => _api ?? (throw StateError('no server chosen'));

  /// `GET` [path] (relative to the base URL) through the same client as
  /// [api], with the answer left undecoded: for a server not yet known to
  /// be kanbot, whose answer is input to check by hand rather than a
  /// contract for the generated decoders (AGENTS.md §5). Throws like
  /// [ApiClient.send].
  Future<http.Response> getUndecoded(String path) {
    final client = _client ?? (throw StateError('no server chosen'));
    return client.get(client.baseUrl.resolve(path));
  }

  /// Talks to [baseUrl] from now on (an API base URL ending in `/`).
  void connect(Uri baseUrl) {
    _client?.close();
    final client = ApiClient(
      httpClient: _newHttpClient(),
      baseUrl: baseUrl,
      tokenStore: _tokenStore,
      onUnauthorized: (token) => onUnauthorized?.call(token),
    );
    _client = client;
    _api = KanbotApi(client, baseUrl: client.baseUrl);
    notifyListeners();
  }

  /// Forgets the server (a native user chose to change it).
  void disconnect() {
    _client?.close();
    _client = null;
    _api = null;
    notifyListeners();
  }

  @override
  void dispose() {
    _client?.close();
    super.dispose();
  }
}
