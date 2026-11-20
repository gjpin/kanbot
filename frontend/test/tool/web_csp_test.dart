import 'package:flutter_test/flutter_test.dart';

import '../../tool/web_csp.dart';

void main() {
  group('contentSecurityPolicy', () {
    final policy = contentSecurityPolicy(
      Uri.parse('https://api.example.com:8443/v1/'),
    );
    final directives = {
      for (final directive in policy.split('; '))
        directive.split(' ').first: directive.split(' ').skip(1).toList(),
    };

    test('denies everything not listed', () {
      expect(directives['default-src'], ["'none'"]);
      expect(directives['object-src'], ["'none'"]);
      expect(directives['form-action'], ["'none'"]);
      expect(directives['base-uri'], ["'self'"]);
    });

    test('allows only same-origin scripts, plus WebAssembly', () {
      expect(directives['script-src'], ["'self'", "'wasm-unsafe-eval'"]);
      expect(policy, isNot(contains('unsafe-eval ')));
      expect(directives['script-src'], isNot(contains("'unsafe-inline'")));
    });

    test('connects only to the app and the API origin', () {
      expect(directives['connect-src'], [
        "'self'",
        'https://api.example.com:8443',
      ]);
    });

    test('loads nothing from other origins', () {
      for (final MapEntry(:key, :value) in directives.entries) {
        final remote = value.where((source) => source.contains('://'));
        expect(
          remote,
          key == 'connect-src' ? ['https://api.example.com:8443'] : isEmpty,
          reason: key,
        );
      }
    });
  });

  group('injectContentSecurityPolicy', () {
    const html =
        '<html>\n<head>\n  <meta charset="UTF-8">\n'
        '  <script src="flutter_bootstrap.js"></script>\n</head>\n</html>';

    test('adds the policy right after the charset', () {
      final result = injectContentSecurityPolicy(html, "default-src 'none'");

      expect(
        result,
        '<html>\n<head>\n  <meta charset="UTF-8">\n'
        '  <meta http-equiv="Content-Security-Policy" '
        'content="default-src \'none\'">\n'
        '  <script src="flutter_bootstrap.js"></script>\n</head>\n</html>',
      );
    });

    test('escapes quotes in the policy', () {
      expect(
        injectContentSecurityPolicy(html, 'a"b'),
        contains('content="a&quot;b"'),
      );
    });

    test('refuses a page without a charset declaration', () {
      expect(
        () => injectContentSecurityPolicy('<html></html>', 'x'),
        throwsFormatException,
      );
    });

    test('refuses a page that already has a policy', () {
      final once = injectContentSecurityPolicy(html, 'x');
      expect(
        () => injectContentSecurityPolicy(once, 'x'),
        throwsFormatException,
      );
    });
  });
}
