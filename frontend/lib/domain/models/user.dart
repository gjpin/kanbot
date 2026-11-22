/// What a user may do across the whole instance, from the identity
/// provider's roles claim.
enum PlatformRole { admin, user }

/// Instance-wide actions the server says the user may take. The app shows
/// only the matching controls; the server checks every request anyway.
enum PlatformPermission {
  createOrganization,
  createTeam,
  searchUsers,
  viewAudit,
}

/// The signed-in user.
final class User {
  const User({
    required this.id,
    required this.displayName,
    required this.role,
    required this.telemetryOptIn,
    required this.permissions,
  });

  final String id;

  /// From the identity provider. Personal data: never log it.
  final String? displayName;
  final PlatformRole role;

  /// Whether the user allows the app to send telemetry.
  final bool telemetryOptIn;
  final Set<PlatformPermission> permissions;

  bool can(PlatformPermission permission) => permissions.contains(permission);
}

/// Another user, as lists show them.
final class UserSummary {
  const UserSummary({
    required this.id,
    required this.displayName,
    this.disabled = false,
  });

  final String id;

  /// From the identity provider. Personal data: never log it.
  final String? displayName;

  /// Disabled in kanbot: listed where they still are, so they can be
  /// removed; they cannot be added anywhere.
  final bool disabled;

  @override
  bool operator ==(Object other) =>
      other is UserSummary &&
      other.id == id &&
      other.displayName == displayName &&
      other.disabled == disabled;

  @override
  int get hashCode => Object.hash(id, displayName, disabled);
}
