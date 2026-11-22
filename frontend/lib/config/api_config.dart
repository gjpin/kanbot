/// A default kanbot server for native apps, set at build time with
/// `--dart-define=API_BASE_URL=https://kanbot.example.com`. Optional: without
/// it, the app asks the user on first launch. The web app ignores it and
/// always talks to the origin it was loaded from.
const String apiBaseUrlDefine = String.fromEnvironment('API_BASE_URL');

/// Whether `API_BASE_URL` was passed at build time.
const bool apiBaseUrlDefined = bool.hasEnvironment('API_BASE_URL');

/// `10.0.2.2`: the host machine as seen from the Android emulator, which
/// local development reaches over plain `http://` too.
const String _emulatorHost = '10.0.2.2';

/// A DNS name (labels of letters, digits and inner `-`), or an IP address
/// (IPv6 without brackets, as [Uri.host] returns it). [Uri.parse]
/// percent-encodes anything else instead of rejecting it.
final RegExp _validHost = RegExp(
  r'^([a-z0-9]([a-z0-9-]*[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.?$'
  r'|^[0-9a-f:.]*:[0-9a-f:.]*$',
);

/// Whether [host] (lower case, as [Uri.host] returns it) is this machine or
/// local development: `localhost` and its subdomains, `127.0.0.0/8`,
/// `0.0.0.0`, the IPv6 loopback in any spelling, IPv4-mapped loopback, and
/// the Android emulator's host.
///
/// `127.0.0.0/8` is a rule for IPv4 addresses only: a DNS name such as
/// `127.example.com` can point anywhere.
bool isLoopbackHost(String host) {
  final name = host.endsWith('.') ? host.substring(0, host.length - 1) : host;
  if (name == 'localhost' || name.endsWith('.localhost')) return true;
  if (name == _emulatorHost || name == '0.0.0.0' || _isLoopbackIPv4(name)) {
    return true;
  }
  if (!name.contains(':')) return false;
  final mapped = name.startsWith('::ffff:') ? name.substring(7) : null;
  if (mapped != null && _isLoopbackIPv4(mapped)) return true;
  // ::1 in any spelling: all groups zero but the last, which is 1.
  final groups = name.split(':').where((group) => group.isNotEmpty).toList();
  return groups.isNotEmpty &&
      int.tryParse(groups.last, radix: 16) == 1 &&
      groups
          .take(groups.length - 1)
          .every((group) => int.tryParse(group, radix: 16) == 0);
}

/// Whether [name] is an IPv4 address in `127.0.0.0/8`, written as four
/// decimal numbers.
bool _isLoopbackIPv4(String name) => switch (_ipv4(name)) {
  [127, ...] => true,
  _ => false,
};

/// The four bytes of the dotted-decimal IPv4 address [name], else `null`.
List<int>? _ipv4(String name) {
  try {
    return Uri.parseIPv4Address(name);
  } on FormatException {
    return null;
  }
}

/// A last label that is a number, decimal or hexadecimal.
final RegExp _numericLabel = RegExp(r'^([0-9]+|0x[0-9a-f]*)$');

/// Whether [host] ends in a number without being a four-number IPv4
/// address. URL parsers and resolvers read such a host as an IPv4 address
/// (`127.1`, `2130706433` and `0x7f.1` all mean `127.0.0.1`), which
/// [isLoopbackHost] would not see; no DNS name ends in a number.
bool _ambiguousNumericHost(String host) {
  final name = host.endsWith('.') ? host.substring(0, host.length - 1) : host;
  if (name.contains(':')) return false;
  return _numericLabel.hasMatch(name.split('.').last) && _ipv4(name) == null;
}

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
      _ambiguousNumericHost(uri.host) ||
      uri.userInfo.isNotEmpty ||
      uri.hasQuery ||
      uri.hasFragment) {
    throw const FormatException(
      'the server URL must be absolute, without credentials, query or '
      'fragment',
    );
  }
  final isLoopback = isLoopbackHost(uri.host);
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
