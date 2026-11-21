//! Every built-in policy, allowed and denied.

use std::net::{IpAddr, Ipv4Addr};

use super::*;
use crate::{
    auth::token::PlatformRole,
    authz::model::{OrganizationFacts, TeamFacts, UserFacts, Via},
    organizations::model::{Access, OrganizationId},
    teams::model::TeamId,
    users::model::{AuthenticatedUser, UserId},
};

fn actor(role: PlatformRole) -> Actor {
    Actor {
        user: AuthenticatedUser {
            id: UserId::new(),
            role,
            display_name: None,
            telemetry_opt_in: false,
            groups: vec!["engineering".to_owned()],
            client_id: Some("kanbot".to_owned()),
        },
        via: Via::Web,
        ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
    }
}

fn decide(actor: &Actor, facts: &Facts, action: Action, resource: Resource) -> Decision {
    Policies::builtin()
        .unwrap()
        .decide(actor, facts, action, resource)
        .unwrap()
}

fn allowed_by(actor: &Actor, facts: &Facts, action: Action, resource: Resource) -> Vec<String> {
    let decision = decide(actor, facts, action, resource);
    assert!(decision.allowed, "{action:?} on {resource:?} is denied");
    decision.policy_ids
}

fn denied(actor: &Actor, facts: &Facts, action: Action, resource: Resource) {
    let decision = decide(actor, facts, action, resource);
    assert!(!decision.allowed, "{action:?} on {resource:?} is allowed");
    assert_eq!(decision.policy_ids, Vec::<String>::new());
}

/// Every action with a resource of its kind.
fn every_request(organization: OrganizationId, team: TeamId) -> Vec<(Action, Resource)> {
    Action::ALL
        .into_iter()
        .map(|action| {
            let resource = match action {
                Action::Read
                | Action::Write
                | Action::ManageOrganization
                | Action::ManageOrganizationAdmins
                | Action::ManageTeamLinks
                | Action::DeleteOrganization
                | Action::LinkOpenShellWorkspace => Resource::Organization(organization),
                Action::ViewTeam
                | Action::ManageTeam
                | Action::ManageTeamMembers
                | Action::SetTeamIdpGroup => Resource::Team(team),
                Action::CreateOrganization
                | Action::CreateTeam
                | Action::SearchUsers
                | Action::ViewAudit => Resource::Platform,
            };
            (action, resource)
        })
        .collect()
}

fn organization(id: OrganizationId, admins: Vec<UserId>) -> OrganizationFacts {
    OrganizationFacts { id, admins }
}

fn team(id: TeamId, maintainers: Vec<UserId>, links: Vec<(OrganizationId, Access)>) -> TeamFacts {
    TeamFacts {
        id,
        maintainers,
        links,
    }
}

/// An organization and a team the actor has nothing to do with.
fn unrelated() -> (OrganizationId, TeamId, Facts) {
    let organization_id = OrganizationId::new();
    let team_id = TeamId::new();
    let facts = Facts {
        user: UserFacts::default(),
        teams: vec![team(
            team_id,
            vec![UserId::new()],
            vec![(organization_id, Access::Write)],
        )],
        organizations: vec![organization(organization_id, vec![UserId::new()])],
    };
    (organization_id, team_id, facts)
}

#[test]
fn the_built_in_policies_validate_against_the_schema() {
    Policies::builtin().unwrap();
}

#[test]
fn platform_admins_may_do_everything() {
    let admin = actor(PlatformRole::Admin);
    let (organization, team, facts) = unrelated();
    for (action, resource) in every_request(organization, team) {
        assert_eq!(
            allowed_by(&admin, &facts, action, resource),
            ["builtin.platform-admins"]
        );
    }
}

#[test]
fn a_plain_user_may_do_nothing_unrelated() {
    let user = actor(PlatformRole::User);
    let (organization, team, facts) = unrelated();
    for (action, resource) in every_request(organization, team) {
        denied(&user, &facts, action, resource);
    }
}

#[test]
fn organization_admins_manage_their_organization() {
    let user = actor(PlatformRole::User);
    let (organization_id, team_id, mut facts) = unrelated();
    facts.organizations = vec![organization(organization_id, vec![user.user.id])];
    facts.user.organization_admin = true;
    let mine = Resource::Organization(organization_id);
    for action in [
        Action::Read,
        Action::Write,
        Action::ManageOrganization,
        Action::ManageOrganizationAdmins,
        Action::ManageTeamLinks,
    ] {
        assert!(
            allowed_by(&user, &facts, action, mine)
                .contains(&"builtin.organization-admins".to_owned()),
            "{action:?}"
        );
    }
    denied(&user, &facts, Action::DeleteOrganization, mine);
    denied(
        &user,
        &facts,
        Action::CreateOrganization,
        Resource::Platform,
    );
    denied(&user, &facts, Action::ViewAudit, Resource::Platform);
    denied(
        &user,
        &facts,
        Action::SetTeamIdpGroup,
        Resource::Team(team_id),
    );
    denied(&user, &facts, Action::ManageTeam, Resource::Team(team_id));
    denied(
        &user,
        &facts,
        Action::ManageTeamMembers,
        Resource::Team(team_id),
    );

    // Another organization's admins are not this one's.
    let other = OrganizationId::new();
    facts
        .organizations
        .push(organization(other, vec![UserId::new()]));
    denied(&user, &facts, Action::Read, Resource::Organization(other));
    denied(
        &user,
        &facts,
        Action::ManageOrganization,
        Resource::Organization(other),
    );
}

#[test]
fn members_of_a_team_with_read_access_may_read() {
    let user = actor(PlatformRole::User);
    let organization_id = OrganizationId::new();
    let team_id = TeamId::new();
    let facts = Facts {
        user: UserFacts {
            teams: vec![team_id],
            ..UserFacts::default()
        },
        teams: vec![team(team_id, vec![], vec![(organization_id, Access::Read)])],
        organizations: vec![organization(organization_id, vec![])],
    };
    let resource = Resource::Organization(organization_id);
    assert_eq!(
        allowed_by(&user, &facts, Action::Read, resource),
        ["builtin.organization-readers"]
    );
    for action in [
        Action::Write,
        Action::ManageOrganization,
        Action::ManageOrganizationAdmins,
        Action::ManageTeamLinks,
        Action::DeleteOrganization,
    ] {
        denied(&user, &facts, action, resource);
    }
}

#[test]
fn members_of_a_team_with_write_access_may_read_and_write() {
    let user = actor(PlatformRole::User);
    let organization_id = OrganizationId::new();
    let team_id = TeamId::new();
    let facts = Facts {
        user: UserFacts {
            teams: vec![team_id],
            ..UserFacts::default()
        },
        teams: vec![team(
            team_id,
            vec![],
            vec![(organization_id, Access::Write)],
        )],
        organizations: vec![organization(organization_id, vec![])],
    };
    let resource = Resource::Organization(organization_id);
    assert_eq!(
        allowed_by(&user, &facts, Action::Read, resource),
        ["builtin.organization-readers"]
    );
    assert_eq!(
        allowed_by(&user, &facts, Action::Write, resource),
        ["builtin.organization-writers"]
    );
    denied(&user, &facts, Action::ManageTeamLinks, resource);
}

#[test]
fn a_link_to_another_organization_gives_nothing_here() {
    let user = actor(PlatformRole::User);
    let here = OrganizationId::new();
    let elsewhere = OrganizationId::new();
    let team_id = TeamId::new();
    let facts = Facts {
        user: UserFacts {
            teams: vec![team_id],
            ..UserFacts::default()
        },
        teams: vec![team(team_id, vec![], vec![(elsewhere, Access::Write)])],
        organizations: vec![organization(here, vec![])],
    };
    denied(&user, &facts, Action::Read, Resource::Organization(here));
    denied(&user, &facts, Action::Write, Resource::Organization(here));
}

#[test]
fn team_maintainers_manage_their_team() {
    let user = actor(PlatformRole::User);
    let team_id = TeamId::new();
    let facts = Facts {
        user: UserFacts {
            teams: vec![team_id],
            team_maintainer: true,
            ..UserFacts::default()
        },
        teams: vec![team(team_id, vec![user.user.id], vec![])],
        organizations: vec![],
    };
    let resource = Resource::Team(team_id);
    for action in [Action::ManageTeam, Action::ManageTeamMembers] {
        assert_eq!(
            allowed_by(&user, &facts, action, resource),
            ["builtin.team-maintainers"]
        );
    }
    denied(&user, &facts, Action::SetTeamIdpGroup, resource);
    denied(&user, &facts, Action::CreateTeam, Resource::Platform);
    assert_eq!(
        allowed_by(&user, &facts, Action::SearchUsers, Resource::Platform),
        ["builtin.user-searchers"]
    );
}

#[test]
fn team_members_see_their_team_and_nothing_more() {
    let user = actor(PlatformRole::User);
    let team_id = TeamId::new();
    let other = TeamId::new();
    let facts = Facts {
        user: UserFacts {
            teams: vec![team_id],
            ..UserFacts::default()
        },
        teams: vec![
            team(team_id, vec![UserId::new()], vec![]),
            team(other, vec![], vec![]),
        ],
        organizations: vec![],
    };
    assert_eq!(
        allowed_by(&user, &facts, Action::ViewTeam, Resource::Team(team_id)),
        ["builtin.team-viewers"]
    );
    denied(&user, &facts, Action::ViewTeam, Resource::Team(other));
    denied(&user, &facts, Action::ManageTeam, Resource::Team(team_id));
    denied(
        &user,
        &facts,
        Action::ManageTeamMembers,
        Resource::Team(team_id),
    );
    denied(&user, &facts, Action::SearchUsers, Resource::Platform);
}

#[test]
fn organization_admins_see_and_create_teams_and_search_users() {
    let user = actor(PlatformRole::User);
    let (_, team_id, mut facts) = unrelated();
    facts.user.organization_admin = true;
    assert_eq!(
        allowed_by(&user, &facts, Action::ViewTeam, Resource::Team(team_id)),
        ["builtin.team-viewers"]
    );
    assert_eq!(
        allowed_by(&user, &facts, Action::CreateTeam, Resource::Platform),
        ["builtin.team-creators"]
    );
    assert_eq!(
        allowed_by(&user, &facts, Action::SearchUsers, Resource::Platform),
        ["builtin.user-searchers"]
    );
}

#[test]
fn an_action_on_the_wrong_kind_of_resource_is_an_error() {
    let user = actor(PlatformRole::Admin);
    let (organization, _, facts) = unrelated();
    let policies = Policies::builtin().unwrap();
    assert!(
        policies
            .decide(&user, &facts, Action::Read, Resource::Platform)
            .is_err()
    );
    assert!(
        policies
            .decide(
                &user,
                &facts,
                Action::CreateTeam,
                Resource::Organization(organization)
            )
            .is_err()
    );
}

#[test]
fn decide_all_answers_each_request_in_order() {
    let user = actor(PlatformRole::User);
    let (organization, team, facts) = unrelated();
    let policies = Policies::builtin().unwrap();
    let admin = actor(PlatformRole::Admin);
    let requests = every_request(organization, team);
    let decisions = policies.decide_all(&admin, &facts, &requests).unwrap();
    assert_eq!(decisions.len(), requests.len());
    assert!(decisions.iter().all(|decision| decision.allowed));
    let decisions = policies.decide_all(&user, &facts, &requests).unwrap();
    assert!(decisions.iter().all(|decision| !decision.allowed));
}

#[test]
fn policies_need_unique_ids() {
    let mut set = PolicySet::new();
    assert!(matches!(
        add_named(
            &mut set,
            "test",
            "permit (principal, action, resource);",
            "x."
        ),
        Err(PolicyError::MissingId { index: 0, .. })
    ));
    let twice = r#"
        @id("a") permit (principal, action, resource);
        @id("a") forbid (principal, action, resource);
    "#;
    assert!(matches!(
        add_named(&mut set, "test", twice, "x."),
        Err(PolicyError::DuplicateId { ref id, .. }) if id == "a"
    ));
    assert!(matches!(
        add_named(&mut set, "test", "permit (", "x."),
        Err(PolicyError::Parse { .. })
    ));
}

/// A writer in the `contractors` group, and an organization they write to.
fn contractor_writer() -> (Actor, Facts, Resource) {
    let mut user = actor(PlatformRole::User);
    user.user.groups = vec!["contractors".to_owned()];
    let organization_id = OrganizationId::new();
    let team_id = TeamId::new();
    let facts = Facts {
        user: UserFacts {
            teams: vec![team_id],
            ..UserFacts::default()
        },
        teams: vec![team(
            team_id,
            vec![],
            vec![(organization_id, Access::Write)],
        )],
        organizations: vec![organization(organization_id, vec![])],
    };
    (user, facts, Resource::Organization(organization_id))
}

const CONTRACTORS_READ_ONLY: &str = r#"
    @id("contractors-read-only")
    forbid (principal, action == Kanbot::Action::"write", resource)
    when { principal.groups.contains("contractors") };
"#;

#[test]
fn a_deployer_forbid_takes_effect() {
    let policies = Policies::with_deployer(CONTRACTORS_READ_ONLY).unwrap();
    let (contractor, facts, resource) = contractor_writer();
    let decision = policies
        .decide(&contractor, &facts, Action::Write, resource)
        .unwrap();
    assert!(!decision.allowed);
    assert_eq!(decision.policy_ids, ["deployer.contractors-read-only"]);
    assert!(
        policies
            .decide(&contractor, &facts, Action::Read, resource)
            .unwrap()
            .allowed
    );

    let mut employee = contractor;
    employee.user.groups = vec!["employees".to_owned()];
    assert!(
        policies
            .decide(&employee, &facts, Action::Write, resource)
            .unwrap()
            .allowed
    );
    // Forbids bind platform admins too.
    let mut admin = actor(PlatformRole::Admin);
    admin.user.groups = vec!["contractors".to_owned()];
    assert!(
        !policies
            .decide(&admin, &facts, Action::Write, resource)
            .unwrap()
            .allowed
    );
}

#[test]
fn deployer_forbids_can_use_the_context() {
    let policies = Policies::with_deployer(
        r#"
        @id("admin-from-the-office")
        forbid (principal, action, resource)
        when { principal.platformRole == "admin" }
        unless { context.ip.isInRange(ip("10.0.0.0/8")) && context.via != "bearer" };
        "#,
    )
    .unwrap();
    let (organization, team, facts) = unrelated();
    let mut admin = actor(PlatformRole::Admin);
    let resource = Resource::Organization(organization);
    admin.ip = "10.1.2.3".parse().unwrap();
    assert!(
        policies
            .decide(&admin, &facts, Action::Read, resource)
            .unwrap()
            .allowed
    );
    admin.via = Via::Bearer;
    assert!(
        !policies
            .decide(&admin, &facts, Action::Read, resource)
            .unwrap()
            .allowed
    );
    admin.via = Via::Native;
    admin.ip = "2001:db8::1".parse().unwrap();
    assert!(
        !policies
            .decide(&admin, &facts, Action::Read, resource)
            .unwrap()
            .allowed
    );
    // Other users are not affected.
    let mut maintainer = actor(PlatformRole::User);
    maintainer.ip = "192.0.2.1".parse().unwrap();
    let facts = Facts {
        teams: vec![team_facts_maintained_by(team, maintainer.user.id)],
        ..facts
    };
    assert!(
        policies
            .decide(
                &maintainer,
                &facts,
                Action::ManageTeam,
                Resource::Team(team)
            )
            .unwrap()
            .allowed
    );
}

fn team_facts_maintained_by(id: TeamId, maintainer: UserId) -> TeamFacts {
    team(id, vec![maintainer], vec![])
}

#[test]
fn a_deployer_permit_is_refused() {
    let named = r#"@id("everyone") permit (principal, action, resource);"#;
    assert!(matches!(
        Policies::with_deployer(named),
        Err(PolicyError::Permit(ref which)) if which == "@id \"everyone\""
    ));
    let mixed = format!("{CONTRACTORS_READ_ONLY} permit (principal, action, resource);");
    assert!(matches!(
        Policies::with_deployer(&mixed),
        Err(PolicyError::Permit(ref which)) if which == "number 1"
    ));
}

#[test]
fn deployer_templates_are_refused() {
    let template = r#"@id("t") forbid (principal == ?principal, action, resource);"#;
    assert!(matches!(
        Policies::with_deployer(template),
        Err(PolicyError::Template)
    ));
}

#[test]
fn deployer_policies_must_validate_and_have_ids() {
    for (text, expected) in [
        (
            r#"@id("x") forbid (principal, action, resource) when { principal.nope };"#,
            "validation",
        ),
        (
            r#"@id("x") forbid (principal, action == Kanbot::Action::"fly", resource);"#,
            "validation",
        ),
        ("forbid (principal, action, resource);", "missing id"),
        ("forbid (", "parse"),
        (
            r#"@id("x") forbid (principal, action, resource);
               @id("x") forbid (principal, action, resource);"#,
            "duplicate",
        ),
    ] {
        let error = Policies::with_deployer(text).err().unwrap();
        let kind = match error {
            PolicyError::Validation(_) => "validation",
            PolicyError::MissingId { source_name, .. } => {
                assert_eq!(source_name, "AUTHZ_POLICY_FILE");
                "missing id"
            }
            PolicyError::Parse { source_name, .. } => {
                assert_eq!(source_name, "AUTHZ_POLICY_FILE");
                "parse"
            }
            PolicyError::DuplicateId { .. } => "duplicate",
            other => panic!("{other}"),
        };
        assert_eq!(kind, expected, "{text}");
    }
}

#[test]
fn an_empty_deployer_file_changes_nothing() {
    let policies = Policies::with_deployer("// nothing yet\n").unwrap();
    let (contractor, facts, resource) = contractor_writer();
    assert!(
        policies
            .decide(&contractor, &facts, Action::Write, resource)
            .unwrap()
            .allowed
    );
}

#[test]
fn the_local_stacks_policies_are_valid() {
    let text = include_str!("../../../dev/policies.cedar");
    let policies = Policies::with_deployer(text).unwrap();
    assert_eq!(
        policies.deployer_policy_ids(),
        ["deployer.contractors-read-only"]
    );
    let (contractor, facts, resource) = contractor_writer();
    assert!(
        !policies
            .decide(&contractor, &facts, Action::Write, resource)
            .unwrap()
            .allowed
    );
}

#[test]
fn the_documented_examples_are_valid() {
    // docs/authorization.md shows the same policies.
    let examples = include_str!("../examples.cedar");
    let policies = Policies::with_deployer(examples).unwrap();
    assert_eq!(
        policies.deployer_policy_ids(),
        [
            "deployer.admin-from-the-office",
            "deployer.ci-reads-only",
            "deployer.contractors-read-only",
            "deployer.freeze-legacy",
        ]
    );
}
