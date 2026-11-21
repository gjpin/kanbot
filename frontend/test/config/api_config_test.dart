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
