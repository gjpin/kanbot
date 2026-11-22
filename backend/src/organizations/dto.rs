//! Request and response types of the `/organizations` routes.

use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::{
    authz::model::Action,
    error::AppError,
    names::{Name, Slug, checked},
    organizations::model::{Access, Organization, OrganizationChanges, OrganizationId, TeamLink},
    users::dto::UserSummaryDto,
};

/// An organization in a list.
#[derive(Debug, Serialize, ToSchema)]
pub struct OrganizationSummaryDto {
    #[schema(value_type = String, format = "uuid")]
    pub id: Uuid,
    pub slug: String,
    pub name: String,
}

/// A page of the organizations the caller may read.
#[derive(Debug, Serialize, ToSchema)]
pub struct OrganizationPageDto {
    pub organizations: Vec<OrganizationSummaryDto>,
    /// Pass as `after` for the next page; `null` on the last one.
    pub next: Option<String>,
}

/// `GET /organizations` parameters.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct OrganizationQuery {
    /// The previous page's `next`.
    pub after: Option<String>,
    /// Organizations per page: 1 to 500, default 100.
    pub limit: Option<i64>,
}

/// An organization, and what the caller may do to it.
#[derive(Debug, Serialize, ToSchema)]
pub struct OrganizationDto {
    #[schema(value_type = String, format = "uuid")]
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    /// The `OpenShell` workspace whose membership kanbot syncs with this
    /// organization, if linked.
    pub openshell_workspace: Option<String>,
    pub permissions: Vec<OrganizationPermissionDto>,
}

/// Something the caller may do to an organization besides reading it.
/// The app shows only the controls the user can use; the server checks
/// every request anyway.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationPermissionDto {
    /// Change the organization's data (features that belong to it).
    Write,
    /// Rename it or change its slug.
    Manage,
    /// Add or remove its admins.
    ManageAdmins,
    /// Link teams to it, change their access, unlink them.
    ManageTeamLinks,
    /// Delete it. Never for the Default organization.
    Delete,
    /// Link it to an `OpenShell` workspace, or unlink it. Only when the
    /// server has the `OpenShell` integration.
    LinkOpenshellWorkspace,
}

/// The `OpenShell` workspace to link an organization to.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct OpenShellLinkDto {
    /// The workspace's name in `OpenShell`. It must exist, and the user
    /// linking it must be able to see it there.
    pub workspace: String,
}

/// A new organization.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewOrganizationDto {
    /// 1 to 63 lowercase letters, digits and hyphens, not starting or
    /// ending with a hyphen. Unique.
    pub slug: String,
    /// 1 to 200 characters.
    pub name: String,
}

/// The fields to change; absent fields stay as they are.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganizationChangesDto {
    pub slug: Option<String>,
    pub name: Option<String>,
}

/// What a linked team's members may do in the organization. `write`
/// includes `read`.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AccessDto {
    Read,
    Write,
}

/// A page of an organization's admins.
#[derive(Debug, Serialize, ToSchema)]
pub struct OrganizationAdminPageDto {
    pub admins: Vec<UserSummaryDto>,
    /// Pass as `after` for the next page; `null` on the last one.
    pub next: Option<String>,
}

/// `GET /organizations/{id}/admins` parameters.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct OrganizationAdminQuery {
    /// The previous page's `next`.
    pub after: Option<String>,
    /// Admins per page: 1 to 500, default 100.
    pub limit: Option<i64>,
}

/// A page of the teams linked to an organization.
#[derive(Debug, Serialize, ToSchema)]
pub struct TeamLinkPageDto {
    pub links: Vec<TeamLinkDto>,
    /// Pass as `after` for the next page; `null` on the last one.
    pub next: Option<String>,
}

/// `GET /organizations/{id}/teams` parameters.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct TeamLinkQuery {
    /// The previous page's `next`.
    pub after: Option<String>,
    /// Linked teams per page: 1 to 500, default 100.
    pub limit: Option<i64>,
}

/// A team linked to an organization.
#[derive(Debug, Serialize, ToSchema)]
pub struct TeamLinkDto {
    pub team: LinkedTeamDto,
    pub access: AccessDto,
}

/// A team linked to an organization, as the organization's readers see
/// it: not its identity provider group, which only those who may see the
/// team learn (`GET /teams/{id}`).
#[derive(Debug, Serialize, ToSchema)]
pub struct LinkedTeamDto {
    #[schema(value_type = String, format = "uuid")]
    pub id: Uuid,
    pub slug: String,
    pub name: String,
}

/// The access to give a linked team.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TeamLinkChangeDto {
    pub access: AccessDto,
}

impl TryFrom<NewOrganizationDto> for Organization {
    type Error = AppError;

    fn try_from(dto: NewOrganizationDto) -> Result<Self, AppError> {
        let mut errors = Vec::new();
        let slug = checked(&mut errors, "/slug", Slug::parse(&dto.slug));
        let name = checked(&mut errors, "/name", Name::parse(&dto.name));
        match (slug, name) {
            (Some(slug), Some(name)) => Ok(Self {
                id: OrganizationId::new(),
                slug,
                name,
                openshell_workspace: None,
            }),
            _ => Err(AppError::Validation(errors)),
        }
    }
}

impl TryFrom<OrganizationChangesDto> for OrganizationChanges {
    type Error = AppError;

    fn try_from(dto: OrganizationChangesDto) -> Result<Self, AppError> {
        let mut errors = Vec::new();
        let slug = dto
            .slug
            .map(|slug| checked(&mut errors, "/slug", Slug::parse(&slug)));
        let name = dto
            .name
            .map(|name| checked(&mut errors, "/name", Name::parse(&name)));
        if errors.is_empty() {
            Ok(Self {
                slug: slug.flatten(),
                name: name.flatten(),
            })
        } else {
            Err(AppError::Validation(errors))
        }
    }
}

impl From<Organization> for OrganizationSummaryDto {
    fn from(organization: Organization) -> Self {
        Self {
            id: organization.id.as_uuid(),
            slug: organization.slug.into_string(),
            name: organization.name.into_string(),
        }
    }
}

impl OrganizationDto {
    #[must_use]
    pub fn new(organization: Organization, permissions: &[Action]) -> Self {
        Self {
            id: organization.id.as_uuid(),
            slug: organization.slug.into_string(),
            name: organization.name.into_string(),
            openshell_workspace: organization
                .openshell_workspace
                .map(|workspace| workspace.as_str().to_owned()),
            permissions: permissions
                .iter()
                .filter_map(|action| match action {
                    Action::Write => Some(OrganizationPermissionDto::Write),
                    Action::ManageOrganization => Some(OrganizationPermissionDto::Manage),
                    Action::ManageOrganizationAdmins => {
                        Some(OrganizationPermissionDto::ManageAdmins)
                    }
                    Action::ManageTeamLinks => Some(OrganizationPermissionDto::ManageTeamLinks),
                    Action::DeleteOrganization => Some(OrganizationPermissionDto::Delete),
                    Action::LinkOpenShellWorkspace => {
                        Some(OrganizationPermissionDto::LinkOpenshellWorkspace)
                    }
                    _ => None,
                })
                .collect(),
        }
    }
}

impl From<AccessDto> for Access {
    fn from(access: AccessDto) -> Self {
        match access {
            AccessDto::Read => Self::Read,
            AccessDto::Write => Self::Write,
        }
    }
}

impl From<TeamLink> for TeamLinkDto {
    fn from(link: TeamLink) -> Self {
        Self {
            team: LinkedTeamDto {
                id: link.team.id.as_uuid(),
                slug: link.team.slug.into_string(),
                name: link.team.name.into_string(),
            },
            access: match link.access {
                Access::Read => AccessDto::Read,
                Access::Write => AccessDto::Write,
            },
        }
    }
}
