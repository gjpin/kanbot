import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';

/// A PKCE pair (RFC 7636) for the native sign-in: the app sends the
/// [challenge] to `/auth/login` and redeems the one-time code with the
/// [verifier], so a code intercepted on its way to the app is useless.
final class Pkce {
  Pkce._(this.verifier) : challenge = challengeOf(verifier);

  /// A new pair: 32 random bytes from [random] (a cryptographically secure
  /// generator by default), base64url without padding (43 characters).
  factory Pkce.generate([Random? random]) {
    final source = random ?? Random.secure();
    final bytes = List<int>.generate(32, (_) => source.nextInt(256));
    return Pkce._(_base64Url(bytes));
  }

  final String verifier;

  /// `S256`: the base64url SHA-256 of the verifier, without padding.
  final String challenge;

  static String challengeOf(String verifier) =>
      _base64Url(sha256.convert(ascii.encode(verifier)).bytes);

  static String _base64Url(List<int> bytes) =>
      base64Url.encode(bytes).replaceAll('=', '');
}
