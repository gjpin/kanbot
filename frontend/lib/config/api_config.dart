/// Base URL of the kanbot backend, set at build time with
/// `--dart-define=API_BASE_URL=https://api.example.com`. Defaults to the
/// backend's local development address.
const String apiBaseUrlDefine = String.fromEnvironment(
  'API_BASE_URL',
  defaultValue: 'http://localhost:3000',
);

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

/// Parses and validates an API base URL (AGENTS.md §2: HTTPS only, except
/// loopback during development).
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
      'API_BASE_URL must be an absolute URL without credentials, query or '
      'fragment',
    );
  }
  final isLoopback = _loopbackHosts.contains(uri.host);
  if (release && isLoopback) {
    throw const FormatException(
      'API_BASE_URL must not point at a loopback host in a release build',
    );
  }
  final isSecure = uri.scheme == 'https';
  final isLocal = uri.scheme == 'http' && isLoopback;
  if (!isSecure && !isLocal) {
    throw const FormatException(
      'API_BASE_URL must use https (http is allowed only for loopback hosts)',
    );
  }
  return uri.path.endsWith('/') ? uri : uri.replace(path: '${uri.path}/');
}

/// The API base URL this build was configured with. Call once at startup:
/// a misconfigured build must fail there, before any request is made.
///
/// A [release] build must set `API_BASE_URL` explicitly; the development
/// default is only for debug and profile builds. [defined] and [raw] exist
/// for tests and default to the build-time values.
///
/// Throws a [FormatException] when the URL is missing (in release) or invalid.
Uri apiBaseUrlFromEnvironment({
  required bool release,
  bool defined = apiBaseUrlDefined,
  String raw = apiBaseUrlDefine,
}) {
  if (release && !defined) {
    throw const FormatException(
      'Release builds must set --dart-define=API_BASE_URL=https://...',
    );
  }
  return parseApiBaseUrl(raw, release: release);
}
