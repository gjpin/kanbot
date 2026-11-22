import 'dart:convert' show HtmlEscape;
import 'dart:io' show IOException;

import 'package:flutter/services.dart';
import 'package:flutter_web_auth_2/flutter_web_auth_2.dart';

/// Signing in was cancelled: the user closed the browser, or it timed out.
final class SignInCancelledException implements Exception {
  const SignInCancelledException();
}

/// The browser hand-off failed for another reason (no browser, the
/// loopback port taken, a platform error).
final class SignInFailedException implements Exception {
  const SignInFailedException();
}

/// Opens the server's sign-in page in the system browser and waits for the
/// redirect back to the app (AGENTS.md §2: only through
/// `flutter_web_auth_2`).
abstract interface class WebAuth {
  /// Opens [url]; completes with the URL the browser was sent to once it
  /// reaches [callback] (a scheme, or `http://127.0.0.1:<port>`).
  ///
  /// Throws [SignInCancelledException] when the user gives up, and
  /// [SignInFailedException] when the hand-off fails otherwise.
  Future<Uri> authenticate({required Uri url, required String callback});
}

/// `FlutterWebAuth2.authenticate`'s signature.
typedef BrowserAuthenticate = Future<String> Function({
  required String url,
  required String callbackUrlScheme,
  FlutterWebAuth2Options options,
});

/// The page the browser shows after the loopback redirect (Windows,
/// Linux), with [title] and [message] (from `Messages`), escaped. The
/// redirect may carry an error as well as a code, so [message] must not
/// say how the sign-in went: the app does.
String landingPage({required String title, required String message}) {
  const escape = HtmlEscape();
  return '<!doctype html><meta charset="utf-8">'
      '<title>${escape.convert(title)}</title>'
      '<p>${escape.convert(message)}</p>';
}

/// [WebAuth] with `flutter_web_auth_2`: `ASWebAuthenticationSession` on
/// Apple platforms, an Auth Tab or Custom Tab on Android, and the system
/// browser with a loopback server on Windows and Linux (never its embedded
/// webview: an app must not see the identity provider's page, RFC 8252).
class FlutterWebAuth implements WebAuth {
  const FlutterWebAuth({
    required this.landingPageHtml,
    this.open = FlutterWebAuth2.authenticate,
  });

  /// How long a sign-in may take, in seconds.
  static const int timeoutSeconds = 300;

  /// Shown in the browser after the loopback redirect (see [landingPage]).
  final String landingPageHtml;

  /// The plugin call; tests replace it.
  final BrowserAuthenticate open;

  @override
  Future<Uri> authenticate({required Uri url, required String callback}) async {
    try {
      final result = await open(
        url: url.toString(),
        callbackUrlScheme: callback,
        options: FlutterWebAuth2Options(
          useWebview: false,
          timeout: timeoutSeconds,
          // A loopback redirect (Windows, Linux) must outlive the app
          // window regaining focus, which happens while the browser opens
          // and whenever the user looks back at the app: closing the
          // server then leaves the browser nowhere to return to. It ends
          // at [timeoutSeconds], or when the user signs in again (the
          // plugin closes it for the new one). With the app's scheme
          // (Android), coming back without the redirect means the user
          // closed the browser.
          cancelOnResume: Uri.parse(callback).scheme != 'http',
          landingPageHtml: landingPageHtml,
        ),
      );
      return Uri.parse(result);
    } on PlatformException catch (error) {
      if (error.code == 'CANCELED') throw const SignInCancelledException();
      throw const SignInFailedException();
    } on FormatException {
      throw const SignInFailedException();
    } on IOException {
      // The loopback server could not listen (Windows, Linux).
      throw const SignInFailedException();
    }
  }
}
