import 'package:kanbot/domain/models/team.dart';

/// What a linked team's members may do in an organization. `write`
/// includes `read`.
enum Access { read, write }

/// Actions the server says the user may take on an organization besides
/// reading it.
enum OrganizationPermission {
  write,
  manage,
  manageAdmins,
  manageTeamLinks,
  delete,
}

/// An organization in a list.
final class OrganizationSummary {
  const OrganizationSummary({
    required this.id,
    required this.slug,
    required this.name,
  });

  final String id;
  final String slug;
  final String name;
}

/// An organization, and what the user may do to it.
final class Organization {
  const Organization({
    required this.id,
    required this.slug,
    required this.name,
    required this.permissions,
  });

  final String id;
  final String slug;
  final String name;
  final Set<OrganizationPermission> permissions;

  bool can(OrganizationPermission permission) =>
      permissions.contains(permission);
}

/// A team linked to an organization.
final class TeamLink {
  const TeamLink({required this.team, required this.access});

  final TeamSummary team;
  final Access access;
}
