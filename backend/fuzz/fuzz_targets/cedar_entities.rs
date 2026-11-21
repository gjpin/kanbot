//! Cedar entities built from arbitrary facts and claims (group names,
//! client IDs, memberships, links): building them and deciding never fails
//! or panics, platform admins are allowed everything, and a user with no
//! memberships or admin rights nothing.
#![no_main]

use std::{net::IpAddr, sync::LazyLock};

use kanbot_backend::{
    auth::token::PlatformRole,
    authz::{
        model::{Action, Actor, Facts, OrganizationFacts, Resource, TeamFacts, UserFacts, Via},
        policies::Policies,
    },
    organizations::model::{Access, OrganizationId},
    teams::model::TeamId,
    users::model::{AuthenticatedUser, UserId},
};
use libfuzzer_sys::fuzz_target;
use uuid::Uuid;

static POLICIES: LazyLock<Policies> =
    LazyLock::new(|| Policies::builtin().expect("built-in policies are valid"));

/// Reads the input a byte at a time; zeros when it runs out.
struct Input<'a>(&'a [u8]);

impl Input<'_> {
    fn byte(&mut self) -> u8 {
        let (first, rest) = self.0.split_first().unwrap_or((&0, &[]));
        self.0 = rest;
        *first
    }

    fn bool(&mut self) -> bool {
        self.byte() & 1 == 1
    }

    /// Up to 15 arbitrary characters.
    fn string(&mut self) -> String {
        let len = usize::from(self.byte() % 16);
        let bytes: Vec<u8> = (0..len).map(|_| self.byte()).collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn id(&mut self) -> Uuid {
        Uuid::from_u128(u128::from(self.byte() % 4))
    }
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data);
    let me = UserId::from_uuid(Uuid::from_u128(u128::MAX));
    let role = if input.bool() {
        PlatformRole::Admin
    } else {
        PlatformRole::User
    };
    let actor = Actor {
        user: AuthenticatedUser {
            id: me,
            role,
            display_name: Some(input.string()),
            telemetry_opt_in: input.bool(),
            groups: (0..input.byte() % 4).map(|_| input.string()).collect(),
            client_id: input.bool().then(|| input.string()),
        },
        via: match input.byte() % 3 {
            0 => Via::Web,
            1 => Via::Native,
            _ => Via::Bearer,
        },
        ip: IpAddr::from([input.byte(), input.byte(), input.byte(), input.byte()]),
    };
    let teams: Vec<TeamFacts> = (0..input.byte() % 4)
        .map(|_| TeamFacts {
            id: TeamId::from_uuid(input.id()),
            maintainers: if input.bool() { vec![me] } else { vec![] },
            links: (0..input.byte() % 3)
                .map(|_| {
                    let access = if input.bool() { Access::Write } else { Access::Read };
                    (OrganizationId::from_uuid(input.id()), access)
                })
                .collect(),
        })
        .collect();
    let mut seen = std::collections::HashSet::new();
    let teams: Vec<TeamFacts> = teams.into_iter().filter(|t| seen.insert(t.id)).collect();
    let organizations: Vec<OrganizationFacts> = (0..4_u128)
        .map(|n| OrganizationFacts {
            id: OrganizationId::from_uuid(Uuid::from_u128(n)),
            admins: if input.bool() { vec![me] } else { vec![] },
        })
        .collect();
    let member_of: Vec<TeamId> = teams.iter().filter(|_| input.bool()).map(|t| t.id).collect();
    let facts = Facts {
        user: UserFacts {
            teams: member_of,
            organization_admin: organizations.iter().any(|o| o.admins.contains(&me)),
            team_maintainer: teams.iter().any(|t| t.maintainers.contains(&me)),
        },
        teams,
        organizations,
    };

    let requests: Vec<(Action, Resource)> = Action::ALL
        .into_iter()
        .flat_map(|action| {
            let resource = match action {
                Action::Read
                | Action::Write
                | Action::ManageOrganization
                | Action::ManageOrganizationAdmins
                | Action::ManageTeamLinks
                | Action::DeleteOrganization => {
                    Resource::Organization(OrganizationId::from_uuid(Uuid::from_u128(0)))
                }
                Action::ViewTeam
                | Action::ManageTeam
                | Action::ManageTeamMembers
                | Action::SetTeamIdpGroup => match facts.teams.first() {
                    Some(team) => Resource::Team(team.id),
                    None => return None,
                },
                Action::CreateOrganization
                | Action::CreateTeam
                | Action::SearchUsers
                | Action::ViewAudit => Resource::Platform,
            };
            Some((action, resource))
        })
        .collect();
    let decisions = POLICIES
        .decide_all(&actor, &facts, &requests)
        .expect("entities from any facts are valid");
    assert_eq!(decisions.len(), requests.len());
    if role == PlatformRole::Admin {
        assert!(decisions.iter().all(|decision| decision.allowed));
    }
    let nothing = facts.user.teams.is_empty()
        && !facts.user.organization_admin
        && !facts.user.team_maintainer;
    if role == PlatformRole::User && nothing {
        assert!(decisions.iter().all(|decision| !decision.allowed));
    }
});
