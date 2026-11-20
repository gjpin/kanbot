import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Keeps the auth token in the platform's secure storage: Keychain on
/// iOS/macOS, Keystore-backed ciphers on Android, libsecret on Linux,
/// DPAPI on Windows, and WebCrypto-wrapped local storage on the web
/// (experimental, see AGENTS.md §2). Never store tokens anywhere else.
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

  /// The stored token, or `null` when signed out.
  Future<String?> read() => _storage.read(key: _tokenKey);

  Future<void> write(String token) =>
      _storage.write(key: _tokenKey, value: token);

  /// Deletes everything this app keeps in secure storage. Call on logout.
  Future<void> clear() => _storage.deleteAll();
}
