import 'package:flutter_test/flutter_test.dart';
import 'package:kanbot/config/api_config.dart';

void main() {
  group('parseApiBaseUrl', () {
    test('accepts https and adds a trailing slash', () {
      for (final release in [false, true]) {
        expect(
          parseApiBaseUrl('https://api.example.com', release: release),
          Uri.parse('https://api.example.com/'),
        );
        expect(
          parseApiBaseUrl('https://api.example.com/v1', release: release),
          Uri.parse('https://api.example.com/v1/'),
        );
        expect(
          parseApiBaseUrl('https://api.example.com/v1/', release: release),
          Uri.parse('https://api.example.com/v1/'),
        );
      }
    });

    const loopbackUrls = [
      'http://localhost:3000',
      'http://127.0.0.1:3000',
      'http://[::1]:3000',
      'http://10.0.2.2:3000',
    ];

    test('accepts http to loopback hosts outside release builds', () {
      for (final raw in loopbackUrls) {
        expect(
          parseApiBaseUrl(raw, release: false),
          Uri.parse('$raw/'),
          reason: raw,
        );
      }
    });

    test('rejects loopback hosts in release builds, even over https', () {
      for (final raw in [
        ...loopbackUrls,
        'https://localhost:3000',
        'https://127.0.0.1',
      ]) {
        expect(
          () => parseApiBaseUrl(raw, release: true),
          throwsFormatException,
          reason: raw,
        );
      }
    });

    test('the default is a valid development URL', () {
      expect(
        parseApiBaseUrl(apiBaseUrlDefine, release: false),
        Uri.parse('http://localhost:3000/'),
      );
    });

    test('rejects insecure, relative and malformed URLs', () {
      for (final release in [false, true]) {
        for (final raw in [
          'http://api.example.com',
          'http://192.168.1.10:3000',
          'ftp://api.example.com',
          'api.example.com',
          '/v1',
          '',
          'https://',
          'https://user:pass@api.example.com',
          'https://api.example.com?x=1',
          'https://api.example.com#top',
          'https://exa mple.com',
        ]) {
          expect(
            () => parseApiBaseUrl(raw, release: release),
            throwsFormatException,
            reason: '$raw (release: $release)',
          );
        }
      }
    });

    test('error messages do not echo the input', () {
      const secret = 'https://user:hunter2@api.example.com';
      expect(
        () => parseApiBaseUrl(secret, release: false),
        throwsA(
          isA<FormatException>().having(
            (e) => e.toString(),
            'message',
            isNot(contains('hunter2')),
          ),
        ),
      );
    });
  });

  group('apiBaseUrlFromEnvironment', () {
    test('uses the development default outside release builds', () {
      expect(
        apiBaseUrlFromEnvironment(
          release: false,
          defined: false,
          raw: 'http://localhost:3000',
        ),
        Uri.parse('http://localhost:3000/'),
      );
    });

    test('requires API_BASE_URL in release builds', () {
      expect(
        () => apiBaseUrlFromEnvironment(
          release: true,
          defined: false,
          raw: 'https://api.example.com',
        ),
        throwsFormatException,
      );
    });

    test('accepts a defined https URL in release builds', () {
      expect(
        apiBaseUrlFromEnvironment(
          release: true,
          defined: true,
          raw: 'https://api.example.com',
        ),
        Uri.parse('https://api.example.com/'),
      );
    });

    test('validates the defined URL', () {
      expect(
        () => apiBaseUrlFromEnvironment(
          release: true,
          defined: true,
          raw: 'http://localhost:3000',
        ),
        throwsFormatException,
      );
      expect(
        () => apiBaseUrlFromEnvironment(
          release: false,
          defined: true,
          raw: 'http://api.example.com',
        ),
        throwsFormatException,
      );
    });

    test('this test build uses the development default', () {
      expect(apiBaseUrlDefined, isFalse);
      expect(
        apiBaseUrlFromEnvironment(release: false),
        Uri.parse('http://localhost:3000/'),
      );
    });
  });
}
