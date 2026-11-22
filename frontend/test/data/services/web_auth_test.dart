import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_web_auth_2/flutter_web_auth_2.dart';
import 'package:kanbot/data/services/web_auth.dart';
import 'package:kanbot/ui/core/messages.dart';

void main() {
  final loginUrl = Uri.parse('https://kanbot.example.com/auth/login?x=1');

  test('returns the redirect, through the system browser', () async {
    final calls = <(String, String, FlutterWebAuth2Options)>[];
    final auth = FlutterWebAuth(
      landingPageHtml: '<p>landing</p>',
      open:
          ({
            required url,
            required callbackUrlScheme,
            options = const FlutterWebAuth2Options(),
          }) async {
            calls.add((url, callbackUrlScheme, options));
            return 'dev.sideral.kanbot:/auth/done?code=kbc_x';
          },
    );

    final result = await auth.authenticate(
      url: loginUrl,
      callback: 'dev.sideral.kanbot',
    );

    expect(result, Uri.parse('dev.sideral.kanbot:/auth/done?code=kbc_x'));
    final (url, callback, options) = calls.single;
    expect(url, loginUrl.toString());
    expect(callback, 'dev.sideral.kanbot');
    // Never an embedded webview (RFC 8252).
    expect(options.useWebview, isFalse);
    expect(options.timeout, FlutterWebAuth.timeoutSeconds);
    expect(options.landingPageHtml, '<p>landing</p>');
  });

  for (final (name, Exception error, Matcher expected) in [
    (
      'the user closing the browser is a cancel',
      PlatformException(code: 'CANCELED'),
      isA<SignInCancelledException>(),
    ),
    (
      'another platform error is a failure',
      PlatformException(code: 'EUNKNOWN'),
      isA<SignInFailedException>(),
    ),
    (
      'a loopback port in use is a failure',
      const SocketException('Address already in use'),
      isA<SignInFailedException>(),
    ),
  ]) {
    test(name, () async {
      final auth = FlutterWebAuth(
        landingPageHtml: '',
        open: ({
          required url,
          required callbackUrlScheme,
          options = const FlutterWebAuth2Options(),
        }) async => throw error,
      );
      await expectLater(
        auth.authenticate(url: loginUrl, callback: 'dev.sideral.kanbot'),
        throwsA(expected),
      );
    });
  }

  test('a redirect that is not a URL is a failure', () async {
    final auth = FlutterWebAuth(
      landingPageHtml: '',
      open: ({
        required url,
        required callbackUrlScheme,
        options = const FlutterWebAuth2Options(),
      }) async => 'http://[::1',
    );
    await expectLater(
      auth.authenticate(url: loginUrl, callback: 'http://127.0.0.1:43210'),
      throwsA(isA<SignInFailedException>()),
    );
  });

  test('the landing page does not claim the sign-in worked', () {
    // The redirect may carry an error (`?error=no_role`) as well as a code.
    final page = landingPage(
      title: Messages.appName,
      message: Messages.signInLanding,
    );
    expect(page, contains(Messages.signInLanding));
    expect(page.toLowerCase(), isNot(contains('signed in')));
    expect(
      landingPage(title: '<t>', message: 'a & <b>'),
      allOf(contains('&lt;t&gt;'), contains('a &amp; &lt;b&gt;')),
    );
  });
}
