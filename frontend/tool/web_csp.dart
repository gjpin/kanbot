/// The Content Security Policy of the release web build, and its injection
/// into `index.html`. Used by `tool/build_web.dart`.
library;

/// The policy for a build that talks to the API at [apiBaseUrl].
///
/// Everything is served from the app's own origin (CanvasKit included: the
/// build uses `--no-web-resources-cdn`). The only other origin the app may
/// reach is the API, which also relays telemetry.
///
/// - `'wasm-unsafe-eval'`: CanvasKit is WebAssembly.
/// - `style-src 'unsafe-inline'`: the engine positions its DOM elements with
///   inline styles. Inline *scripts* stay forbidden.
/// - `blob:`/`data:` images and fonts: the engine decodes images and loads
///   bundled fonts from in-memory URLs.
///
/// `frame-ancestors` cannot be set from a `<meta>` tag; the web server must
/// send it as a header.
String contentSecurityPolicy(Uri apiBaseUrl) {
  final apiOrigin = apiBaseUrl.origin;
  return [
    "default-src 'none'",
    "script-src 'self' 'wasm-unsafe-eval'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data: blob:",
    "connect-src 'self' $apiOrigin",
    "worker-src 'self' blob:",
    "manifest-src 'self'",
    "base-uri 'self'",
    "form-action 'none'",
    "object-src 'none'",
  ].join('; ');
}

const String _charsetMeta = '<meta charset="UTF-8">';

/// Inserts the policy as a `<meta http-equiv>` tag right after the charset
/// declaration, before any script or stylesheet can load.
///
/// Throws a [FormatException] when [html] has no charset `<meta>` tag or
/// already declares a policy.
String injectContentSecurityPolicy(String html, String policy) {
  if (html.contains('Content-Security-Policy')) {
    throw const FormatException('index.html already declares a CSP');
  }
  final index = html.indexOf(_charsetMeta);
  if (index < 0) {
    throw const FormatException('index.html has no <meta charset="UTF-8">');
  }
  final end = index + _charsetMeta.length;
  final escaped = policy.replaceAll('"', '&quot;');
  return '${html.substring(0, end)}\n'
      '  <meta http-equiv="Content-Security-Policy" content="$escaped">'
      '${html.substring(end)}';
}
