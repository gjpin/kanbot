import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Keeps the kanbot session token (`kbs_...`) in the platform's secure
/// storage. Native apps only: the web app stores no token (its session is
/// an `HttpOnly` cookie). Secure storage is: Keychain on iOS/macOS,
/// Keystore-backed ciphers on Android, libsecret on Linux and DPAPI on
/// Windows. Never store tokens anywhere else.
///
/// The token is stored together with the server that issued it, in one
/// entry, and [read] gives it only to that server: whatever path changes
/// the server (the user choosing another one, a stored server that is no
/// longer valid, storage that could not be read), the token never reaches
/// another one.
class TokenStore {
  TokenStore({this._storage = defaultStorage});

  /// Keychain items are readable after the first unlock (so background work
  /// can use them) and never leave this device: no iCloud sync, no restore
  /// onto another device.
  ///
  /// macOS uses the legacy keychain, which needs no `keychain-access-groups`
  /// entitlement or provisioning profile. Switch to the data protection
  /// keychain once the app is signed with an Apple Developer team.
  static const FlutterSecureStorage defaultStorage = FlutterSecureStorage(
    iOptions: IOSOptions(
      accessibility: KeychainAccessibility.first_unlock_this_device,
    ),
    mOptions: MacOsOptions(
      accessibility: KeychainAccessibility.first_unlock_this_device,
      usesDataProtectionKeychain: false,
    ),
  );

  static const String _tokenKey = 'auth_token';

  final FlutterSecureStorage _storage;

  /// The stored value for [token] issued by [server]: the server's API base
  /// URL, a space (which a URL never contains unencoded) and the token.
  /// Tests use it to set up storage.
  static String entry(Uri server, String token) => '$server $token';

  /// The token [server] issued, or `null` when signed out, or when the
  /// stored token belongs to another server.
  Future<String?> read({required Uri server}) async {
    final stored = await _storage.read(key: _tokenKey);
    if (stored == null) return null;
    final separator = stored.indexOf(' ');
    if (separator < 0) return null;
    if (stored.substring(0, separator) != server.toString()) return null;
    return stored.substring(separator + 1);
  }

  /// Stores [token], issued by [server], in place of any other.
  Future<void> write(String token, {required Uri server}) =>
      _storage.write(key: _tokenKey, value: entry(server, token));

  /// Deletes the token. Call on logout. The chosen server (`ServerStore`)
  /// stays.
  Future<void> clear() => _storage.delete(key: _tokenKey);
}
