//! Domain types of authorization: who asks, to do what, to which resource,
//! and the facts from the database a decision needs.

use std::net::IpAddr;

use crate::{
    organizations::model::{Access, OrganizationId},
    teams::model::TeamId,
    users::model::{AuthenticatedUser, UserId},
};

/// A Cedar action (`Kanbot::Action::"<name>"`, see `schema.cedarschema`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    /// Read an organization's data.
    Read,
    /// Change an organization's data.
    Write,
    /// Rename an organization.
    ManageOrganization,
    /// Add or remove an organization's admins.
    ManageOrganizationAdmins,
    /// Link teams to an organization, or unlink them.
    ManageTeamLinks,
    DeleteOrganization,
    /// Link the organization to an `OpenShell` workspace, or unlink it.
    LinkOpenShellWorkspace,
    /// See a team and its members.
    ViewTeam,
    /// Rename or delete a team.
    ManageTeam,
    /// Add or remove a team's members, or change their role.
    ManageTeamMembers,
    /// Set or clear the identity provider group a team is synced with.
    SetTeamIdpGroup,
    CreateOrganization,
    CreateTeam,
    /// Find users by name, to add them as admins or members.
    SearchUsers,
    /// Read the audit log.
    ViewAudit,
}

impl Action {
    pub const ALL: [Self; 15] = [
        Self::Read,
        Self::Write,
        Self::ManageOrganization,
        Self::ManageOrganizationAdmins,
        Self::ManageTeamLinks,
        Self::DeleteOrganization,
        Self::LinkOpenShellWorkspace,
        Self::ViewTeam,
        Self::ManageTeam,
        Self::ManageTeamMembers,
        Self::SetTeamIdpGroup,
        Self::CreateOrganization,
        Self::CreateTeam,
        Self::SearchUsers,
        Self::ViewAudit,
    ];

    /// The Cedar action's name, also used in the audit log.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::ManageOrganization => "manageOrganization",
            Self::ManageOrganizationAdmins => "manageOrganizationAdmins",
            Self::ManageTeamLinks => "manageTeamLinks",
            Self::DeleteOrganization => "deleteOrganization",
            Self::LinkOpenShellWorkspace => "linkOpenShellWorkspace",
            Self::ViewTeam => "viewTeam",
            Self::ManageTeam => "manageTeam",
            Self::ManageTeamMembers => "manageTeamMembers",
            Self::SetTeamIdpGroup => "setTeamIdpGroup",
            Self::CreateOrganization => "createOrganization",
            Self::CreateTeam => "createTeam",
            Self::SearchUsers => "searchUsers",
            Self::ViewAudit => "viewAudit",
        }
    }
}

/// What an action is done to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Resource {
    /// The whole instance.
    Platform,
    Organization(OrganizationId),
    Team(TeamId),
}

/// How a request was authenticated (Cedar `context.via`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Via {
    /// The web app's session cookie.
    Web,
    /// A native app's session token.
    Native,
    /// An identity provider's access token.
    Bearer,
}

impl Via {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Web => "web",
            Self::Native => "native",
            Self::Bearer => "bearer",
        }
    }
}

/// Who asks: the Cedar principal and the request context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Actor {
    pub user: AuthenticatedUser,
    pub via: Via,
    /// The client's address.
    pub ip: IpAddr,
}

/// A decision, and the policies that made it: the permits that allowed it,
/// or the forbids that denied it (none when no permit applied).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub allowed: bool,
    pub policy_ids: Vec<String>,
}

/// What the database says about the actor, for a decision.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UserFacts {
    /// The teams the actor is a member of (any role, any source).
    pub teams: Vec<TeamId>,
    /// Whether the actor administers at least one organization.
    pub organization_admin: bool,
    /// Whether the actor maintains at least one team.
    pub team_maintainer: bool,
}

/// A team in a decision: one of the actor's, or the resource.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TeamFacts {
    pub id: TeamId,
    pub maintainers: Vec<UserId>,
    /// The organizations the team is linked to.
    pub links: Vec<(OrganizationId, Access)>,
}

/// An organization that is a resource in a decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrganizationFacts {
    pub id: OrganizationId,
    pub admins: Vec<UserId>,
}

/// Everything a set of decisions needs from the database.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Facts {
    pub user: UserFacts,
    /// The actor's teams and every team that is a resource.
    pub teams: Vec<TeamFacts>,
    /// Every organization that is a resource.
    pub organizations: Vec<OrganizationFacts>,
}
