//! Authorization against the database: `can`, `require` and `visible`.

pub mod common;

use std::net::{IpAddr, Ipv4Addr};

use kanbot_backend::{
    auth::token::PlatformRole,
    authz::{
        model::{Action, Actor, Resource, Via},
        policies::Policies,
        service,
    },
    error::AppError,
    organizations::model::OrganizationId,
    teams::model::TeamId,
    users::model::{AuthenticatedUser, UserId},
};
use proptest::{prelude::*, test_runner::TestRunner};
use sqlx::PgPool;
use uuid::Uuid;

fn actor(id: Uuid, role: PlatformRole, groups: &[&str]) -> Actor {
    Actor {
        user: AuthenticatedUser {
            id: UserId::from_uuid(id),
            role,
            display_name: None,
            telemetry_opt_in: false,
            groups: groups.iter().map(|group| (*group).to_owned()).collect(),
            client_id: None,
        },
        via: Via::Bearer,
        ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
    }
}

async fn insert_user(pool: &PgPool, role: PlatformRole) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query!(
        "INSERT INTO users (id, issuer, subject, platform_role) VALUES ($1, 'https://idp', $2, $3)",
        id,
        id.to_string(),
        role.as_str()
    )
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn insert_team(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query!(
        "INSERT INTO teams (id, slug, name) VALUES ($1, $2, 'Team')",
        id,
        format!("t{}", id.simple())
    )
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn insert_organization(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query!(
        "INSERT INTO organizations (id, slug, name) VALUES ($1, $2, 'Org')",
        id,
        format!("o{}", id.simple())
    )
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn add_member(pool: &PgPool, team: Uuid, user: Uuid, role: &str) {
    sqlx::query!(
        "INSERT INTO team_members (team_id, user_id, role, source) VALUES ($1, $2, $3, 'manual')",
        team,
        user,
        role
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn link(pool: &PgPool, organization: Uuid, team: Uuid, access: &str) {
    sqlx::query!(
        "INSERT INTO organization_teams (organization_id, team_id, access) VALUES ($1, $2, $3)",
        organization,
        team,
        access
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn add_admin(pool: &PgPool, organization: Uuid, user: Uuid) {
    sqlx::query!(
        "INSERT INTO organization_admins (organization_id, user_id) VALUES ($1, $2)",
        organization,
        user
    )
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test]
async fn can_reads_memberships_and_links(pool: PgPool) {
    let policies = Policies::builtin().unwrap();
    let user = insert_user(&pool, PlatformRole::User).await;
    let team = insert_team(&pool).await;
    let organization = insert_organization(&pool).await;
    let alice = actor(user, PlatformRole::User, &[]);
    let resource = Resource::Organization(OrganizationId::from_uuid(organization));

    let can = |action| service::can(&pool, &policies, &alice, action, resource);
    assert!(!can(Action::Read).await.unwrap().allowed);

    add_member(&pool, team, user, "member").await;
    link(&pool, organization, team, "read").await;
    let decision = can(Action::Read).await.unwrap();
    assert!(decision.allowed);
    assert_eq!(decision.policy_ids, ["builtin.organization-readers"]);
    assert!(!can(Action::Write).await.unwrap().allowed);

    sqlx::query!("UPDATE organization_teams SET access = 'write'")
        .execute(&pool)
        .await
        .unwrap();
    assert!(can(Action::Write).await.unwrap().allowed);
    assert!(!can(Action::ManageTeamLinks).await.unwrap().allowed);

    add_admin(&pool, organization, user).await;
    assert!(can(Action::ManageTeamLinks).await.unwrap().allowed);
    assert!(
        service::can(
            &pool,
            &policies,
            &alice,
            Action::CreateTeam,
            Resource::Platform
        )
        .await
        .unwrap()
        .allowed
    );
}

#[sqlx::test]
async fn team_maintainers_come_from_the_database(pool: PgPool) {
    let policies = Policies::builtin().unwrap();
    let user = insert_user(&pool, PlatformRole::User).await;
    let team = insert_team(&pool).await;
    let alice = actor(user, PlatformRole::User, &[]);
    let resource = Resource::Team(TeamId::from_uuid(team));
    let can = |action, resource| service::can(&pool, &policies, &alice, action, resource);

    add_member(&pool, team, user, "member").await;
    assert!(can(Action::ViewTeam, resource).await.unwrap().allowed);
    assert!(
        !can(Action::ManageTeamMembers, resource)
            .await
            .unwrap()
            .allowed
    );
    assert!(
        !can(Action::SearchUsers, Resource::Platform)
            .await
            .unwrap()
            .allowed
    );

    sqlx::query!("UPDATE team_members SET role = 'maintainer'")
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        can(Action::ManageTeamMembers, resource)
            .await
            .unwrap()
            .allowed
    );
    assert!(
        can(Action::SearchUsers, Resource::Platform)
            .await
            .unwrap()
            .allowed
    );
}

#[sqlx::test]
async fn resources_that_do_not_exist_are_not_found(pool: PgPool) {
    let policies = Policies::builtin().unwrap();
    let admin = actor(
        insert_user(&pool, PlatformRole::Admin).await,
        PlatformRole::Admin,
        &[],
    );
    for resource in [
        Resource::Organization(OrganizationId::new()),
        Resource::Team(TeamId::new()),
    ] {
        let action = match resource {
            Resource::Team(_) => Action::ViewTeam,
            _ => Action::Read,
        };
        assert!(matches!(
            service::can(&pool, &policies, &admin, action, resource).await,
            Err(AppError::NotFound)
        ));
        assert!(matches!(
            service::require(&pool, &policies, &admin, action, resource).await,
            Err(AppError::NotFound)
        ));
    }
}

#[sqlx::test]
async fn require_hides_what_the_actor_may_not_know(pool: PgPool) {
    let policies = Policies::builtin().unwrap();
    let user = insert_user(&pool, PlatformRole::User).await;
    let alice = actor(user, PlatformRole::User, &[]);
    let team = insert_team(&pool).await;
    let organization = OrganizationId::from_uuid(insert_organization(&pool).await);
    let require = |action, resource| service::require(&pool, &policies, &alice, action, resource);

    // Unknown to the actor: not found, whatever the action.
    for action in [Action::Read, Action::Write, Action::DeleteOrganization] {
        assert!(matches!(
            require(action, Resource::Organization(organization)).await,
            Err(AppError::NotFound)
        ));
    }
    assert!(matches!(
        require(Action::ManageTeam, Resource::Team(TeamId::from_uuid(team))).await,
        Err(AppError::NotFound)
    ));

    // Known, but not allowed: forbidden.
    add_member(&pool, team, user, "member").await;
    link(&pool, organization.as_uuid(), team, "read").await;
    let decision = require(Action::Read, Resource::Organization(organization))
        .await
        .unwrap();
    assert_eq!(decision.policy_ids, ["builtin.organization-readers"]);
    assert!(matches!(
        require(Action::Write, Resource::Organization(organization)).await,
        Err(AppError::Forbidden)
    ));
    assert!(matches!(
        require(Action::ManageTeam, Resource::Team(TeamId::from_uuid(team))).await,
        Err(AppError::Forbidden)
    ));
    // The platform is known to everyone.
    assert!(matches!(
        require(Action::CreateOrganization, Resource::Platform).await,
        Err(AppError::Forbidden)
    ));
}

/// Random users, teams, organizations, memberships, links and admins, by
/// index.
#[derive(Clone, Debug)]
struct World {
    admins: Vec<bool>,
    teams: usize,
    organizations: usize,
    members: Vec<(usize, usize, bool)>,
    links: Vec<(usize, usize, bool)>,
    organization_admins: Vec<(usize, usize)>,
    contractors: Vec<bool>,
}

fn world() -> impl Strategy<Value = World> {
    (1..4_usize, 0..4_usize, 0..4_usize).prop_flat_map(|(users, teams, organizations)| {
        (
            prop::collection::vec(any::<bool>(), users),
            prop::collection::vec((0..users, 0..teams.max(1), any::<bool>()), 0..8),
            prop::collection::vec(
                (0..organizations.max(1), 0..teams.max(1), any::<bool>()),
                0..8,
            ),
            prop::collection::vec((0..organizations.max(1), 0..users), 0..4),
            prop::collection::vec(any::<bool>(), users),
        )
            .prop_map(
                move |(admins, members, links, organization_admins, contractors)| World {
                    admins,
                    teams,
                    organizations,
                    members: if teams == 0 { vec![] } else { members },
                    links: if teams == 0 || organizations == 0 {
                        vec![]
                    } else {
                        links
                    },
                    organization_admins: if organizations == 0 {
                        vec![]
                    } else {
                        organization_admins
                    },
                    contractors,
                },
            )
    })
}

/// Loads `world` into an empty database, and checks that each user's
/// `visible_*` lists equal Cedar's decision on every organization and
/// team: the SQL pre-filter never drops one Cedar allows.
/// Replaces the database's content with `world`. Returns the users with
/// their roles, the teams and the organizations it created.
async fn load_world(
    pool: &PgPool,
    world: &World,
) -> (Vec<(Uuid, PlatformRole)>, Vec<Uuid>, Vec<Uuid>) {
    sqlx::query!(
        "TRUNCATE team_members, organization_teams, organization_admins, teams, audit_log, users CASCADE"
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query!(
        "DELETE FROM organizations WHERE id <> $1",
        OrganizationId::DEFAULT.as_uuid()
    )
    .execute(pool)
    .await
    .unwrap();

    let mut users = Vec::new();
    for admin in &world.admins {
        let role = if *admin {
            PlatformRole::Admin
        } else {
            PlatformRole::User
        };
        users.push((insert_user(pool, role).await, role));
    }
    let mut teams = Vec::new();
    for _ in 0..world.teams {
        teams.push(insert_team(pool).await);
    }
    let mut organizations = Vec::new();
    for _ in 0..world.organizations {
        organizations.push(insert_organization(pool).await);
    }
    let mut seen = std::collections::HashSet::new();
    for (user, team, maintainer) in &world.members {
        if seen.insert(("member", *user, *team)) {
            let role = if *maintainer { "maintainer" } else { "member" };
            add_member(pool, teams[*team], users[*user].0, role).await;
        }
    }
    for (organization, team, write) in &world.links {
        if seen.insert(("link", *organization, *team)) {
            let access = if *write { "write" } else { "read" };
            link(pool, organizations[*organization], teams[*team], access).await;
        }
    }
    for (organization, user) in &world.organization_admins {
        if seen.insert(("admin", *organization, *user)) {
            add_admin(pool, organizations[*organization], users[*user].0).await;
        }
    }
    (users, teams, organizations)
}

async fn check_visible(pool: &PgPool, policies: &Policies, world: &World) {
    let (users, teams, organizations) = load_world(pool, world).await;
    for (index, (user, role)) in users.iter().enumerate() {
        let groups: &[&str] = if world.contractors[index] {
            &["contractors"]
        } else {
            &[]
        };
        let actor = actor(*user, *role, groups);
        let mut allowed = Vec::new();
        for organization in
            std::iter::once(&OrganizationId::DEFAULT.as_uuid()).chain(&organizations)
        {
            let organization = OrganizationId::from_uuid(*organization);
            let resource = Resource::Organization(organization);
            if service::can(pool, policies, &actor, Action::Read, resource)
                .await
                .unwrap()
                .allowed
            {
                allowed.push(organization);
            }
        }
        let mut visible = service::visible_organizations(pool, policies, &actor)
            .await
            .unwrap();
        allowed.sort();
        visible.sort();
        assert_eq!(visible, allowed, "organizations of user {index}: {world:?}");

        let mut allowed = Vec::new();
        for team in &teams {
            let team = TeamId::from_uuid(*team);
            if service::can(
                pool,
                policies,
                &actor,
                Action::ViewTeam,
                Resource::Team(team),
            )
            .await
            .unwrap()
            .allowed
            {
                allowed.push(team);
            }
        }
        let mut visible = service::visible_teams(pool, policies, &actor)
            .await
            .unwrap();
        allowed.sort();
        visible.sort();
        assert_eq!(visible, allowed, "teams of user {index}: {world:?}");
    }
}

/// `visible_*` relies on deployer policies being forbid-only; with forbids
/// in place (here on contractors), the lists must still match Cedar.
#[sqlx::test]
async fn visible_lists_match_cedar_for_random_data(pool: PgPool) {
    let builtin = Policies::builtin().unwrap();
    let forbids = Policies::with_deployer(
        r#"
        @id("contractors-see-nothing")
        forbid (principal, action == Kanbot::Action::"read", resource)
        when { principal.groups.contains("contractors") };
        @id("no-team-viewing-for-contractors")
        forbid (principal, action == Kanbot::Action::"viewTeam", resource)
        when { principal.groups.contains("contractors") };
        "#,
    )
    .unwrap();
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        let mut runner = TestRunner::new(ProptestConfig {
            cases: 32,
            ..ProptestConfig::default()
        });
        runner
            .run(&world(), |world| {
                handle.block_on(async {
                    check_visible(&pool, &builtin, &world).await;
                    check_visible(&pool, &forbids, &world).await;
                });
                Ok(())
            })
            .unwrap();
    })
    .await
    .unwrap();
}

#[sqlx::test]
async fn visible_lists_are_sorted_by_slug(pool: PgPool) {
    let policies = Policies::builtin().unwrap();
    let admin = actor(
        insert_user(&pool, PlatformRole::Admin).await,
        PlatformRole::Admin,
        &[],
    );
    for slug in ["zeta", "alpha", "mid"] {
        sqlx::query!(
            "INSERT INTO organizations (id, slug, name) VALUES ($1, $2, 'Org')",
            Uuid::new_v4(),
            slug
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query!(
            "INSERT INTO teams (id, slug, name) VALUES ($1, $2, 'Team')",
            Uuid::new_v4(),
            slug
        )
        .execute(&pool)
        .await
        .unwrap();
    }
    let slugs = |table: &'static str| {
        let pool = pool.clone();
        async move {
            match table {
                "organizations" => {
                    sqlx::query_scalar!("SELECT slug FROM organizations ORDER BY slug")
                        .fetch_all(&pool)
                        .await
                        .unwrap()
                }
                _ => sqlx::query_scalar!("SELECT slug FROM teams ORDER BY slug")
                    .fetch_all(&pool)
                    .await
                    .unwrap(),
            }
        }
    };
    let organizations = service::visible_organizations(&pool, &policies, &admin)
        .await
        .unwrap();
    let mut listed = Vec::new();
    for id in organizations {
        listed.push(
            sqlx::query_scalar!("SELECT slug FROM organizations WHERE id = $1", id.as_uuid())
                .fetch_one(&pool)
                .await
                .unwrap(),
        );
    }
    assert_eq!(listed, slugs("organizations").await);
    assert_eq!(listed, ["alpha", "default", "mid", "zeta"]);

    let teams = service::visible_teams(&pool, &policies, &admin)
        .await
        .unwrap();
    let mut listed = Vec::new();
    for id in teams {
        listed.push(
            sqlx::query_scalar!("SELECT slug FROM teams WHERE id = $1", id.as_uuid())
                .fetch_one(&pool)
                .await
                .unwrap(),
        );
    }
    assert_eq!(listed, slugs("teams").await);
}

#[sqlx::test]
async fn a_deployer_forbid_applies_to_the_api(pool: PgPool) {
    use axum::http::StatusCode;
    use common::api::{Api, admin, user};
    use serde_json::json;

    let policies = Policies::with_deployer(
        r#"
        @id("contractors-create-nothing")
        forbid (principal, action == Kanbot::Action::"createTeam", resource)
        when { principal.groups.contains("contractors") };
        "#,
    )
    .unwrap();
    let api = Api::of(common::app_with_policies(
        pool.clone(),
        std::sync::Arc::new(policies),
    ));
    let root = admin("root");
    let mut admins = Vec::new();
    for (subject, groups) in [("dave", &["contractors"][..]), ("erin", &[][..])] {
        let token = user(subject, groups);
        let id = api.user_id(&token).await;
        api.put(
            &format!(
                "/organizations/{}/admins/{id}",
                OrganizationId::DEFAULT.as_uuid()
            ),
            &root,
            None,
        )
        .await;
        admins.push(token);
    }
    let [dave, erin] = admins.try_into().unwrap();

    let new_team = json!({ "slug": "x", "name": "X" });
    let (status, body) = api.post("/teams", &dave, new_team.clone()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        api.get("/me", &dave).await.1["permissions"],
        json!(["search_users"])
    );
    assert_eq!(
        api.post("/teams", &erin, new_team).await.0,
        StatusCode::CREATED
    );
    assert_eq!(
        api.get("/me", &erin).await.1["permissions"],
        json!(["create_team", "search_users"])
    );
}
