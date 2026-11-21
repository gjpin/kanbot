import 'package:flutter/services.dart';
import 'package:flutter_web_auth_2/flutter_web_auth_2.dart';

/// Signing in was cancelled: the user closed the browser, or it timed out.
final class SignInCancelledException implements Exception {
  const SignInCancelledException();
}

/// Opens the server's sign-in page in the system browser and waits for the
/// redirect back to the app (AGENTS.md §2: only through
/// `flutter_web_auth_2`).
abstract interface class WebAuth {
  /// Opens [url]; completes with the URL the browser was sent to once it
  /// reaches [callback] (a scheme, or `http://127.0.0.1:<port>`).
  ///
  /// Throws [SignInCancelledException] when the user gives up.
  Future<Uri> authenticate({required Uri url, required String callback});
}

/// [WebAuth] with `flutter_web_auth_2`: `ASWebAuthenticationSession` on
/// Apple platforms, an Auth Tab or Custom Tab on Android, and the system
/// browser with a loopback server on Windows and Linux (never its embedded
/// webview: an app must not see the identity provider's page, RFC 8252).
class FlutterWebAuth implements WebAuth {
  const FlutterWebAuth();

  /// How long a sign-in may take, in seconds.
  static const int timeoutSeconds = 300;

  /// Shown in the browser after the loopback redirect (Windows, Linux).
  static const String landingPage =
      '<!doctype html><meta charset="utf-8"><title>kanbot</title>'
      '<p>You are signed in. You can close this window and return to '
      'kanbot.</p>';

  @override
  Future<Uri> authenticate({required Uri url, required String callback}) async {
    try {
      final result = await FlutterWebAuth2.authenticate(
        url: url.toString(),
        callbackUrlScheme: callback,
        options: const FlutterWebAuth2Options(
          useWebview: false,
          timeout: timeoutSeconds,
          landingPageHtml: landingPage,
        ),
      );
      return Uri.parse(result);
    } on PlatformException catch (error) {
      if (error.code == 'CANCELED') throw const SignInCancelledException();
      rethrow;
    }
  }
}
