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
        'https://127.0.0.2',
        'https://localhost.',
        'https://api.localhost',
        'https://0.0.0.0',
        'https://[0:0:0:0:0:0:0:1]',
        'https://[::ffff:127.0.0.1]',
      ]) {
        expect(
          () => parseApiBaseUrl(raw, release: true),
          throwsFormatException,
          reason: raw,
        );
      }
    });

    test('a DNS name starting with 127 is not loopback', () {
      // Plain http to it would carry the session token in clear text.
      for (final raw in [
        'http://127.attacker.example',
        'http://127.0.0.1.attacker.example',
        'http://[::ffff:127.attacker]',
      ]) {
        expect(
          () => parseApiBaseUrl(raw, release: false),
          throwsFormatException,
          reason: raw,
        );
      }
      // And a release build may use it.
      expect(
        parseApiBaseUrl('https://127.example.com', release: true),
        Uri.parse('https://127.example.com/'),
      );
    });

    test('rejects hosts that only resolvers read as IPv4 addresses', () {
      // All 127.0.0.1, which a four-number check would not see.
      for (final release in [false, true]) {
        for (final raw in [
          'https://127.1',
          'https://2130706433',
          'https://0x7f.1',
          'https://0x7f000001',
          'https://127.0.0.256',
          'https://example.0x10',
        ]) {
          expect(
            () => parseApiBaseUrl(raw, release: release),
            throwsFormatException,
            reason: '$raw (release: $release)',
          );
        }
      }
      expect(
        parseApiBaseUrl('https://192.0.2.10', release: true),
        Uri.parse('https://192.0.2.10/'),
      );
      expect(
        parseApiBaseUrl('https://example.0xg', release: true),
        Uri.parse('https://example.0xg/'),
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
          'https://..',
          'https://---',
          'https://-a.example.com',
          'https://a..example.com',
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

  test('isLoopbackHost applies 127.0.0.0/8 to IPv4 addresses only', () {
    for (final host in [
      '127.0.0.1',
      '127.255.255.254',
      '127.0.0.1.',
      '::ffff:127.0.0.1',
      'localhost',
    ]) {
      expect(isLoopbackHost(host), isTrue, reason: host);
    }
    for (final host in [
      '127.example.com',
      '127.attacker.example',
      '127.0.0.1.example.com',
      '127.1',
      '::ffff:127.example',
      '128.0.0.1',
    ]) {
      expect(isLoopbackHost(host), isFalse, reason: host);
    }
  });

  group('defaultServerUrl', () {
    test('is optional', () {
      for (final release in [false, true]) {
        expect(
          defaultServerUrl(release: release, defined: false, raw: ''),
          isNull,
        );
      }
    });

    test('validates a defined URL as the build requires', () {
      expect(
        defaultServerUrl(
          release: true,
          defined: true,
          raw: 'https://kanbot.example.com',
        ),
        Uri.parse('https://kanbot.example.com/'),
      );
      expect(
        defaultServerUrl(
          release: false,
          defined: true,
          raw: 'http://localhost:3000',
        ),
        Uri.parse('http://localhost:3000/'),
      );
      for (final (release, raw) in [
        (true, 'http://localhost:3000'),
        (false, 'http://kanbot.example.com'),
        (false, ''),
      ]) {
        expect(
          () => defaultServerUrl(release: release, defined: true, raw: raw),
          throwsFormatException,
          reason: raw,
        );
      }
    });

    test('this test build has no default server', () {
      expect(apiBaseUrlDefined, isFalse);
      expect(defaultServerUrl(release: false), isNull);
    });
  });

  test('the web app talks to the origin it was loaded from', () {
    expect(
      webApiBaseUrl(Uri.parse('https://kanbot.example.com/teams/1?x=2#y')),
      Uri.parse('https://kanbot.example.com/'),
    );
    expect(
      webApiBaseUrl(Uri.parse('http://localhost:3000/login?error=no_role')),
      Uri.parse('http://localhost:3000/'),
    );
  });
}
