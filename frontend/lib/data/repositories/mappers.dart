import 'package:kanbot/data/api/generated/kanbot_api.dart' as api;
import 'package:kanbot/domain/models/audit.dart';
import 'package:kanbot/domain/models/organization.dart';
import 'package:kanbot/domain/models/server.dart';
import 'package:kanbot/domain/models/team.dart';
import 'package:kanbot/domain/models/user.dart';

// Generated types never leave the repositories (AGENTS.md §3). Values a
// newer server may add (unknown enum values) map to the least privileged
// reading: an unknown permission is left out, an unknown role or access is
// the lowest one, an unknown membership source is read-only.

User userFrom(api.Me me) => User(
  id: me.id,
  displayName: me.displayName,
  role: switch (me.platformRole) {
    api.PlatformRoleDtoKnown(value: api.PlatformRoleDtoValue.admin) =>
      PlatformRole.admin,
    _ => PlatformRole.user,
  },
  telemetryOptIn: me.telemetryOptIn,
  permissions: {
    for (final permission in me.permissions)
      if (permission case api.PlatformPermissionDtoKnown(:final value))
        switch (value) {
          api.PlatformPermissionDtoValue.createOrganization =>
            PlatformPermission.createOrganization,
          api.PlatformPermissionDtoValue.createTeam =>
            PlatformPermission.createTeam,
          api.PlatformPermissionDtoValue.searchUsers =>
            PlatformPermission.searchUsers,
          api.PlatformPermissionDtoValue.viewAudit =>
            PlatformPermission.viewAudit,
        },
  },
);

UserSummary userSummaryFrom(api.UserSummaryDto user) => UserSummary(
  id: user.id,
  displayName: user.displayName,
  disabled: user.disabled,
);

ServerInfo serverInfoFrom(api.AuthConfig config) => ServerInfo(
  loginUrl: Uri.parse(config.loginUrl),
  telemetryAvailable: config.telemetryAvailable,
  version: config.version,
);

OrganizationSummary organizationSummaryFrom(api.OrganizationSummaryDto dto) =>
    OrganizationSummary(id: dto.id, slug: dto.slug, name: dto.name);

Organization organizationFrom(api.OrganizationDto dto) => Organization(
  id: dto.id,
  slug: dto.slug,
  name: dto.name,
  openShellWorkspace: dto.openshellWorkspace,
  permissions: {
    for (final permission in dto.permissions)
      if (permission case api.OrganizationPermissionDtoKnown(:final value))
        switch (value) {
          api.OrganizationPermissionDtoValue.write =>
            OrganizationPermission.write,
          api.OrganizationPermissionDtoValue.manage =>
            OrganizationPermission.manage,
          api.OrganizationPermissionDtoValue.manageAdmins =>
            OrganizationPermission.manageAdmins,
          api.OrganizationPermissionDtoValue.manageTeamLinks =>
            OrganizationPermission.manageTeamLinks,
          api.OrganizationPermissionDtoValue.delete =>
            OrganizationPermission.delete,
          api.OrganizationPermissionDtoValue.linkOpenshellWorkspace =>
            OrganizationPermission.linkOpenShellWorkspace,
        },
  },
);

Access accessFrom(api.AccessDto dto) => switch (dto) {
  api.AccessDtoKnown(value: api.AccessDtoValue.write) => Access.write,
  _ => Access.read,
};

api.AccessDto accessTo(Access access) => switch (access) {
  Access.read => api.AccessDto.read,
  Access.write => api.AccessDto.write,
};

/// An organization's readers do not learn a linked team's identity
/// provider group.
TeamLink teamLinkFrom(api.TeamLinkDto dto) => TeamLink(
  team: TeamSummary(
    id: dto.team.id,
    slug: dto.team.slug,
    name: dto.team.name,
    idpGroup: null,
  ),
  access: accessFrom(dto.access),
);

TeamSummary teamSummaryFrom(api.TeamSummaryDto dto) => TeamSummary(
  id: dto.id,
  slug: dto.slug,
  name: dto.name,
  idpGroup: dto.idpGroup,
);

Team teamFrom(api.TeamDto dto) => Team(
  id: dto.id,
  slug: dto.slug,
  name: dto.name,
  idpGroup: dto.idpGroup,
  permissions: {
    for (final permission in dto.permissions)
      if (permission case api.TeamPermissionDtoKnown(:final value))
        switch (value) {
          api.TeamPermissionDtoValue.manage => TeamPermission.manage,
          api.TeamPermissionDtoValue.manageMembers =>
            TeamPermission.manageMembers,
          api.TeamPermissionDtoValue.setIdpGroup => TeamPermission.setIdpGroup,
        },
  },
);

Member memberFrom(api.MemberDto dto) => Member(
  user: userSummaryFrom(dto.user),
  role: switch (dto.role) {
    api.TeamRoleDtoKnown(value: api.TeamRoleDtoValue.maintainer) =>
      TeamRole.maintainer,
    _ => TeamRole.member,
  },
  source: switch (dto.source) {
    api.MembershipSourceDtoKnown(value: api.MembershipSourceDtoValue.manual) =>
      MembershipSource.manual,
    _ => MembershipSource.idp,
  },
);

api.TeamRoleDto teamRoleTo(TeamRole role) => switch (role) {
  TeamRole.member => api.TeamRoleDto.member,
  TeamRole.maintainer => api.TeamRoleDto.maintainer,
};

AuditPage auditPageFrom(api.AuditPage dto) => AuditPage(
  entries: [
    for (final entry in dto.entries)
      AuditEntry(
        id: entry.id,
        at: entry.at,
        actor: userSummaryFrom(entry.actor),
        action: entry.action,
        targetType: entry.targetType,
        targetId: entry.targetId,
        policyIds: entry.policyIds,
      ),
  ],
  nextBefore: dto.nextBefore,
);
