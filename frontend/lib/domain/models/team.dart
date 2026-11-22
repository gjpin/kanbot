import 'package:kanbot/domain/models/user.dart';

/// Actions the server says the user may take on a team besides seeing it.
enum TeamPermission { manage, manageMembers, setIdpGroup }

/// A member's role in a team.
enum TeamRole { member, maintainer }

/// How a member got into a team.
enum MembershipSource {
  /// Added in kanbot.
  manual,

  /// From the identity provider group; read-only.
  idp,
}

/// A team in a list.
final class TeamSummary {
  const TeamSummary({
    required this.id,
    required this.slug,
    required this.name,
    required this.idpGroup,
  });

  final String id;
  final String slug;
  final String name;

  /// Set: the members come from this identity provider group.
  final String? idpGroup;
}

/// A team, and what the user may do to it.
final class Team {
  const Team({
    required this.id,
    required this.slug,
    required this.name,
    required this.idpGroup,
    required this.permissions,
  });

  final String id;
  final String slug;
  final String name;

  /// Set: the members come from this identity provider group.
  final String? idpGroup;
  final Set<TeamPermission> permissions;

  bool can(TeamPermission permission) => permissions.contains(permission);
}

/// A member of a team.
final class Member {
  const Member({required this.user, required this.role, required this.source});

  final UserSummary user;
  final TeamRole role;
  final MembershipSource source;
}

/// A page of a team's members; [next] fetches the following one.
final class MemberPage {
  const MemberPage({required this.members, this.next});

  final List<Member> members;

  /// Opaque: where the next page starts, or `null` on the last one.
  final String? next;
}
