import 'dart:math';

import 'package:flutter_test/flutter_test.dart';
import 'package:kanbot/data/services/pkce.dart';

void main() {
  test('S256 matches RFC 7636, appendix B', () {
    expect(
      Pkce.challengeOf('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'),
      'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    );
  });

  test('verifiers are 32 random bytes in base64url', () {
    final pkce = Pkce.generate(Random(1));
    expect(pkce.verifier, matches(RegExp(r'^[A-Za-z0-9_-]{43}$')));
    expect(pkce.challenge, Pkce.challengeOf(pkce.verifier));
    expect(Pkce.generate(Random(1)).verifier, pkce.verifier);
    expect(Pkce.generate(Random(2)).verifier, isNot(pkce.verifier));
    // The default source is the secure one: two pairs never repeat.
    expect(Pkce.generate().verifier, isNot(Pkce.generate().verifier));
  });
}
