/// A default kanbot server for native apps, set at build time with
/// `--dart-define=API_BASE_URL=https://kanbot.example.com`. Optional: without
/// it, the app asks the user on first launch. The web app ignores it and
/// always talks to the origin it was loaded from.
const String apiBaseUrlDefine = String.fromEnvironment('API_BASE_URL');

/// Whether `API_BASE_URL` was passed at build time.
const bool apiBaseUrlDefined = bool.hasEnvironment('API_BASE_URL');

/// Hosts that may be reached over plain `http://` during local development.
/// `10.0.2.2` is the host machine as seen from the Android emulator.
const Set<String> _loopbackHosts = {
  'localhost',
  '127.0.0.1',
  '::1',
  '10.0.2.2',
};

/// A DNS name, IPv4 address or (bracket-less, as [Uri.host] returns it) IPv6
/// address. [Uri.parse] percent-encodes anything else instead of rejecting it.
final RegExp _validHost = RegExp(r'^[a-z0-9.:-]+$');

/// Parses and validates a kanbot server URL, the API base URL (AGENTS.md
/// §2: HTTPS only, except loopback during development).
///
/// A [release] build accepts only `https://` URLs to hosts other than the
/// loopback ones: a release that talks to `localhost` is a build mistake.
///
/// The returned URL always ends with `/`, so relative paths resolve below it.
///
/// Throws a [FormatException] when [raw] is not an absolute `https://` URL
/// (or, outside release builds, `http://` to a loopback host), or carries
/// credentials, a query or a fragment.
Uri parseApiBaseUrl(String raw, {required bool release}) {
  final uri = Uri.tryParse(raw);
  if (uri == null ||
      !_validHost.hasMatch(uri.host) ||
      uri.userInfo.isNotEmpty ||
      uri.hasQuery ||
      uri.hasFragment) {
    throw const FormatException(
      'the server URL must be absolute, without credentials, query or '
      'fragment',
    );
  }
  final isLoopback = _loopbackHosts.contains(uri.host);
  if (release && isLoopback) {
    throw const FormatException(
      'the server URL must not point at a loopback host in a release build',
    );
  }
  final isSecure = uri.scheme == 'https';
  final isLocal = uri.scheme == 'http' && isLoopback;
  if (!isSecure && !isLocal) {
    throw const FormatException(
      'the server URL must use https (http only for loopback hosts)',
    );
  }
  return uri.path.endsWith('/') ? uri : uri.replace(path: '${uri.path}/');
}

/// The default server this build was configured with, if any. Call once at
/// startup: a misconfigured build must fail there, before any request is
/// made. [defined] and [raw] exist for tests and default to the build-time
/// values.
///
/// Throws a [FormatException] when `API_BASE_URL` is set but invalid.
Uri? defaultServerUrl({
  required bool release,
  bool defined = apiBaseUrlDefined,
  String raw = apiBaseUrlDefine,
}) => defined ? parseApiBaseUrl(raw, release: release) : null;

/// The API base URL of the web app: the origin of [page], the URL it was
/// loaded from. The backend serves the web build and the API together
/// (`WEB_DIR`), so the session cookie and CSRF checks work.
Uri webApiBaseUrl(Uri page) => Uri(
  scheme: page.scheme,
  host: page.host,
  port: page.hasPort ? page.port : null,
  path: '/',
);
