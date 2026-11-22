import 'package:flutter_test/flutter_test.dart';

import '../../tool/build_web.dart';

void main() {
  test('refuses API_BASE_URL in every form flutter build takes', () {
    for (final args in [
      ['--dart-define=API_BASE_URL=https://x.example.com'],
      ['--dart-define', 'API_BASE_URL=https://x.example.com'],
      ['--dart-define-from-file=defines.json'],
      ['--dart-define-from-file', 'defines.json'],
    ]) {
      expect(definesApiBaseUrl(args), isTrue, reason: '$args');
    }
    for (final args in [
      <String>[],
      ['--wasm'],
      ['--dart-define=OTEL_SERVICE_VERSION=1.0.0'],
      ['--dart-define', 'OTEL_SERVICE_VERSION=1.0.0'],
    ]) {
      expect(definesApiBaseUrl(args), isFalse, reason: '$args');
    }
  });
}
