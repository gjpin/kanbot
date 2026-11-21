import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Keeps the kanbot session token (`kbs_...`) in the platform's secure
/// storage. Native apps only: the web app stores no token (its session is
/// an `HttpOnly` cookie). Secure storage is: Keychain on iOS/macOS,
/// Keystore-backed ciphers on Android, libsecret on Linux and DPAPI on
/// Windows. Never store tokens anywhere else.
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

  /// Deletes the token. Call on logout. The chosen server (`ServerStore`)
  /// stays.
  Future<void> clear() => _storage.delete(key: _tokenKey);
}
