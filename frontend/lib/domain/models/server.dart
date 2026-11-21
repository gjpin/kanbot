/// What a kanbot server says about itself before anyone signs in.
final class ServerInfo {
  const ServerInfo({
    required this.loginUrl,
    required this.telemetryAvailable,
    required this.version,
  });

  /// Where sign-ins start (`/auth/login`).
  final Uri loginUrl;

  /// Whether the server relays the app's telemetry.
  final bool telemetryAvailable;
  final String version;
}
