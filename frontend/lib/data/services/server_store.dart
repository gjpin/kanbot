import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:kanbot/config/api_config.dart';
import 'package:kanbot/data/services/token_store.dart';

/// Remembers which kanbot server a native app talks to. Not a secret, but
/// kept in the same secure storage as the session token (AGENTS.md §2: no
/// other storage for auth data), under its own key: signing out keeps it.
class ServerStore {
  ServerStore({this._storage = TokenStore.defaultStorage});

  static const String _serverKey = 'server_url';

  final FlutterSecureStorage _storage;

  /// The stored server, validated as [parseApiBaseUrl] does for a
  /// [release] build. `null` when none is stored, or when the stored value
  /// is no longer valid (it is then forgotten).
  Future<Uri?> read({required bool release}) async {
    final raw = await _storage.read(key: _serverKey);
    if (raw == null) return null;
    try {
      return parseApiBaseUrl(raw, release: release);
    } on FormatException {
      await clear();
      return null;
    }
  }

  Future<void> write(Uri server) =>
      _storage.write(key: _serverKey, value: server.toString());

  Future<void> clear() => _storage.delete(key: _serverKey);
}
