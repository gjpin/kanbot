//! Request and response types of the `/teams` routes.

use serde::{Deserialize, Deserializer, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    authz::model::Action,
    error::AppError,
    names::{Name, Slug, checked},
    teams::model::{
        IdpGroup, IdpGroupChange, Member, MembershipSource, Team, TeamChanges, TeamId, TeamRole,
    },
    users::dto::UserSummaryDto,
};

/// A team in a list.
#[derive(Debug, Serialize, ToSchema)]
pub struct TeamSummaryDto {
    #[schema(value_type = String, format = "uuid")]
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    /// Set: the members are the users whose groups claim contains this
    /// identity provider group, and they cannot be edited.
    pub idp_group: Option<String>,
}

/// A team, and what the caller may do to it.
#[derive(Debug, Serialize, ToSchema)]
pub struct TeamDto {
    #[schema(value_type = String, format = "uuid")]
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    /// Set: the members are the users whose groups claim contains this
    /// identity provider group, and they cannot be edited.
    pub idp_group: Option<String>,
    pub permissions: Vec<TeamPermissionDto>,
}

/// Something the caller may do to a team besides seeing it. The app shows
/// only the controls the user can use; the server checks every request
/// anyway.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TeamPermissionDto {
    /// Rename it, change its slug or delete it.
    Manage,
    /// Add or remove members and change their role. Never for a team
    /// synced with an identity provider group.
    ManageMembers,
    /// Set or clear its identity provider group.
    SetIdpGroup,
}

/// A new team. Its creator becomes its maintainer.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewTeamDto {
    /// 1 to 63 lowercase letters, digits and hyphens, not starting or
    /// ending with a hyphen. Unique.
    pub slug: String,
    /// 1 to 200 characters.
    pub name: String,
}

/// The fields to change; absent fields stay as they are.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TeamChangesDto {
    pub slug: Option<String>,
    pub name: Option<String>,
    /// An identity provider group to sync the members with, or `null` to
    /// stop syncing. Platform admins only. Setting a group removes the
    /// current members; the group's members join as they sign in.
    /// Clearing it removes the synced members.
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub idp_group: IdpGroupPatch,
}

/// `idp_group` in a change: absent, `null` or a group.
#[derive(Debug, Default)]
pub enum IdpGroupPatch {
    #[default]
    Unchanged,
    Clear,
    Set(String),
}

impl<'de> Deserialize<'de> for IdpGroupPatch {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match Option::<String>::deserialize(deserializer)? {
            Some(group) => Self::Set(group),
            None => Self::Clear,
        })
    }
}

/// A team member's role.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TeamRoleDto {
    Member,
    /// Manages the team and its members.
    Maintainer,
}

/// How a member got into the team.
#[derive(Clone, Copy, Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MembershipSourceDto {
    /// Added through the API.
    Manual,
    /// From the identity provider group; read-only.
    Idp,
}

/// A member of a team.
#[derive(Debug, Serialize, ToSchema)]
pub struct MemberDto {
    pub user: UserSummaryDto,
    pub role: TeamRoleDto,
    pub source: MembershipSourceDto,
}

/// The role to give a member.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct MemberChangeDto {
    pub role: TeamRoleDto,
}

impl TryFrom<NewTeamDto> for Team {
    type Error = AppError;

    fn try_from(dto: NewTeamDto) -> Result<Self, AppError> {
        let mut errors = Vec::new();
        let slug = checked(&mut errors, "/slug", Slug::parse(&dto.slug));
        let name = checked(&mut errors, "/name", Name::parse(&dto.name));
        match (slug, name) {
            (Some(slug), Some(name)) => Ok(Self {
                id: TeamId::new(),
                slug,
                name,
                idp_group: None,
            }),
            _ => Err(AppError::Validation(errors)),
        }
    }
}

impl TryFrom<TeamChangesDto> for TeamChanges {
    type Error = AppError;

    fn try_from(dto: TeamChangesDto) -> Result<Self, AppError> {
        let mut errors = Vec::new();
        let slug = dto
            .slug
            .map(|slug| checked(&mut errors, "/slug", Slug::parse(&slug)));
        let name = dto
            .name
            .map(|name| checked(&mut errors, "/name", Name::parse(&name)));
        let idp_group = match dto.idp_group {
            IdpGroupPatch::Unchanged => None,
            IdpGroupPatch::Clear => Some(IdpGroupChange::Clear),
            IdpGroupPatch::Set(group) => {
                checked(&mut errors, "/idp_group", IdpGroup::parse(&group)).map(IdpGroupChange::Set)
            }
        };
        if errors.is_empty() {
            Ok(Self {
                slug: slug.flatten(),
                name: name.flatten(),
                idp_group,
            })
        } else {
            Err(AppError::Validation(errors))
        }
    }
}

impl From<Team> for TeamSummaryDto {
    fn from(team: Team) -> Self {
        Self {
            id: team.id.as_uuid(),
            slug: team.slug.into_string(),
            name: team.name.into_string(),
            idp_group: team.idp_group.map(|group| group.as_str().to_owned()),
        }
    }
}

impl TeamDto {
    #[must_use]
    pub fn new(team: Team, permissions: &[Action]) -> Self {
        Self {
            id: team.id.as_uuid(),
            slug: team.slug.into_string(),
            name: team.name.into_string(),
            idp_group: team.idp_group.map(|group| group.as_str().to_owned()),
            permissions: permissions
                .iter()
                .filter_map(|action| match action {
                    Action::ManageTeam => Some(TeamPermissionDto::Manage),
                    Action::ManageTeamMembers => Some(TeamPermissionDto::ManageMembers),
                    Action::SetTeamIdpGroup => Some(TeamPermissionDto::SetIdpGroup),
                    _ => None,
                })
                .collect(),
        }
    }
}

impl From<TeamRoleDto> for TeamRole {
    fn from(role: TeamRoleDto) -> Self {
        match role {
            TeamRoleDto::Member => Self::Member,
            TeamRoleDto::Maintainer => Self::Maintainer,
        }
    }
}

impl From<Member> for MemberDto {
    fn from(member: Member) -> Self {
        Self {
            user: member.user.into(),
            role: match member.role {
                TeamRole::Member => TeamRoleDto::Member,
                TeamRole::Maintainer => TeamRoleDto::Maintainer,
            },
            source: match member.source {
                MembershipSource::Manual => MembershipSourceDto::Manual,
                MembershipSource::Idp => MembershipSourceDto::Idp,
            },
        }
    }
}
