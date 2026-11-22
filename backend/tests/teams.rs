//! Teams: identity provider group sync, and the `/teams` routes.

pub mod common;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use common::{
    api::{Api, admin, user},
    idp::access_token,
};
use kanbot_backend::{teams::service, users::model::UserId};
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

async fn insert_user(pool: &PgPool) -> UserId {
    let id = Uuid::new_v4();
    sqlx::query!(
        "INSERT INTO users (id, issuer, subject, platform_role) VALUES ($1, 'https://idp', $2, 'user')",
        id,
        id.to_string()
    )
    .execute(pool)
    .await
    .unwrap();
    UserId::from_uuid(id)
}

async fn insert_team(pool: &PgPool, slug: &str, idp_group: Option<&str>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query!(
        "INSERT INTO teams (id, slug, name, idp_group) VALUES ($1, $2, 'Team', $3)",
        id,
        slug,
        idp_group
    )
    .execute(pool)
    .await
    .unwrap();
    id
}

/// The user's memberships: (team, role, source), by team ID.
async fn memberships(pool: &PgPool, user: UserId) -> Vec<(Uuid, String, String)> {
    sqlx::query!(
        "SELECT team_id, role, source FROM team_members WHERE user_id = $1 ORDER BY team_id",
        user.as_uuid()
    )
    .fetch_all(pool)
    .await
    .unwrap()
    .into_iter()
    .map(|row| (row.team_id, row.role, row.source))
    .collect()
}

/// The versions of every membership row: they change on every write.
async fn row_versions(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar!(
        r#"SELECT xmin::text AS "version!" FROM team_members ORDER BY team_id, user_id"#
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

fn groups(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

#[sqlx::test]
async fn sync_adds_and_removes_idp_memberships(pool: PgPool) {
    let user = insert_user(&pool).await;
    let platform = insert_team(&pool, "platform", Some("platform-team")).await;
    let ops = insert_team(&pool, "ops", Some("ops-team")).await;
    insert_team(&pool, "manual", None).await;

    service::sync_idp_groups(&pool, user, &groups(&["platform-team", "unrelated"]))
        .await
        .unwrap();
    assert_eq!(
        memberships(&pool, user).await,
        [(platform, "member".to_owned(), "idp".to_owned())]
    );

    service::sync_idp_groups(&pool, user, &groups(&["ops-team"]))
        .await
        .unwrap();
    assert_eq!(
        memberships(&pool, user).await,
        [(ops, "member".to_owned(), "idp".to_owned())]
    );

    service::sync_idp_groups(&pool, user, &[]).await.unwrap();
    assert_eq!(memberships(&pool, user).await, []);
}

#[sqlx::test]
async fn sync_leaves_manual_memberships_alone(pool: PgPool) {
    let user = insert_user(&pool).await;
    let manual = insert_team(&pool, "manual", None).await;
    sqlx::query!(
        "INSERT INTO team_members (team_id, user_id, role, source) VALUES ($1, $2, 'maintainer', 'manual')",
        manual,
        user.as_uuid()
    )
    .execute(&pool)
    .await
    .unwrap();
    let synced = insert_team(&pool, "synced", Some("synced")).await;

    service::sync_idp_groups(&pool, user, &groups(&["synced"]))
        .await
        .unwrap();
    service::sync_idp_groups(&pool, user, &[]).await.unwrap();

    assert_eq!(
        memberships(&pool, user).await,
        [(manual, "maintainer".to_owned(), "manual".to_owned())]
    );
    assert_ne!(manual, synced);
}

#[sqlx::test]
async fn sync_writes_only_when_something_changed(pool: PgPool) {
    let user = insert_user(&pool).await;
    insert_team(&pool, "a", Some("a")).await;
    insert_team(&pool, "b", Some("b")).await;
    let other = insert_user(&pool).await;
    service::sync_idp_groups(&pool, user, &groups(&["a", "b"]))
        .await
        .unwrap();
    service::sync_idp_groups(&pool, other, &groups(&["a"]))
        .await
        .unwrap();
    let before = row_versions(&pool).await;
    assert_eq!(before.len(), 3);

    service::sync_idp_groups(&pool, user, &groups(&["b", "a"]))
        .await
        .unwrap();
    assert_eq!(row_versions(&pool).await, before);

    // Another user's change leaves this user's rows alone.
    service::sync_idp_groups(&pool, other, &[]).await.unwrap();
    assert_eq!(memberships(&pool, user).await.len(), 2);
}

async fn get_me(app: &Router, token: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::get("/me")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

#[sqlx::test]
async fn every_authenticated_request_syncs_the_groups(pool: PgPool) {
    let app = common::app_with_pool(pool.clone());
    let team = insert_team(&pool, "platform", Some("platform-team")).await;

    assert_eq!(
        get_me(
            &app,
            &access_token("alice", &["kanbot-user", "platform-team"])
        )
        .await,
        StatusCode::OK
    );
    let alice = UserId::from_uuid(
        sqlx::query_scalar!("SELECT id FROM users WHERE subject = 'alice'")
            .fetch_one(&pool)
            .await
            .unwrap(),
    );
    assert_eq!(
        memberships(&pool, alice).await,
        [(team, "member".to_owned(), "idp".to_owned())]
    );

    assert_eq!(
        get_me(&app, &access_token("alice", &["kanbot-user"])).await,
        StatusCode::OK
    );
    assert_eq!(memberships(&pool, alice).await, []);
}

#[sqlx::test]
async fn a_token_without_the_groups_claim_keeps_the_memberships(pool: PgPool) {
    // Roles and groups in separate claims: a token from another client may
    // carry the roles without the groups.
    let keys = common::idp::static_key_cache_with(&[("OIDC_GROUPS_CLAIM", "teams")]);
    let app = common::app_with_keys(pool.clone(), &kanbot_backend::db::MIGRATOR, keys);
    let team = insert_team(&pool, "platform", Some("platform-team")).await;
    let token = |teams: Option<&[&str]>| {
        let mut claims = common::idp::claims("alice", &["kanbot-user"]);
        if let Some(teams) = teams {
            claims["teams"] = serde_json::json!(teams);
        }
        common::idp::sign("rsa-a", &claims)
    };

    assert_eq!(
        get_me(&app, &token(Some(&["platform-team"]))).await,
        StatusCode::OK
    );
    let alice = UserId::from_uuid(
        sqlx::query_scalar!("SELECT id FROM users WHERE subject = 'alice'")
            .fetch_one(&pool)
            .await
            .unwrap(),
    );
    assert_eq!(memberships(&pool, alice).await.len(), 1);

    assert_eq!(get_me(&app, &token(None)).await, StatusCode::OK);
    assert_eq!(
        memberships(&pool, alice).await,
        [(team, "member".to_owned(), "idp".to_owned())],
        "unknown groups are not no groups"
    );
    assert_eq!(get_me(&app, &token(Some(&[]))).await, StatusCode::OK);
    assert_eq!(memberships(&pool, alice).await, []);
}

fn team_slugs(list: &Value) -> Vec<&str> {
    list.as_array()
        .unwrap()
        .iter()
        .map(|item| item["slug"].as_str().unwrap())
        .collect()
}

/// The members as (display name, role, source).
async fn member_list(api: &Api, team: Uuid, token: &str) -> Vec<(String, String, String)> {
    let (status, list) = api.get(&format!("/teams/{team}/members"), token).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    list.as_array()
        .unwrap()
        .iter()
        .map(|member| {
            (
                member["user"]["display_name"].as_str().unwrap().to_owned(),
                member["role"].as_str().unwrap().to_owned(),
                member["source"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

fn row(name: &str, role: &str, source: &str) -> (String, String, String) {
    (name.to_owned(), role.to_owned(), source.to_owned())
}

#[sqlx::test]
async fn organization_admins_create_teams_and_maintain_them(pool: PgPool) {
    let api = Api::new(pool.clone());
    let root = admin("root");
    let carol = user("carol", &[]);
    let carol_id = api.user_id(&carol).await;
    let bob = user("bob", &[]);
    assert_eq!(
        api.post("/teams", &bob, json!({ "slug": "x", "name": "X" }))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    // An organization admin may create teams.
    api.put(
        &format!("/organizations/00000000-0000-0000-0000-000000000001/admins/{carol_id}"),
        &root,
        None,
    )
    .await;
    let (status, body) = api
        .post(
            "/teams",
            &carol,
            json!({ "slug": "platform", "name": "Platform" }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["idp_group"], Value::Null);
    assert_eq!(body["permissions"], json!(["manage", "manage_members"]));
    let team: Uuid = body["id"].as_str().unwrap().parse().unwrap();
    assert_eq!(
        member_list(&api, team, &carol).await,
        [row("carol (display)", "maintainer", "manual")]
    );
    let (status, body) = api
        .post(
            "/teams",
            &carol,
            json!({ "slug": "platform", "name": "Again" }),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let (status, body) = api
        .post("/teams", &carol, json!({ "slug": "", "name": "x" }))
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        body["errors"],
        json!([{ "pointer": "/slug", "code": "required" }])
    );
}

#[sqlx::test]
async fn maintainers_manage_members(pool: PgPool) {
    let api = Api::new(pool.clone());
    let root = admin("root");
    let team = api.team(&root, "platform").await;
    let bob = user("bob", &[]);
    let bob_id = api.user_id(&bob).await;
    let dave = user("dave", &[]);
    let dave_id = api.user_id(&dave).await;
    let eve = user("eve", &[]);
    let members = format!("/teams/{team}/members");

    // Strangers do not know the team exists.
    assert_eq!(
        api.get(&format!("/teams/{team}"), &bob).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(api.get("/teams", &bob).await.1, json!([]));

    let (status, _) = api
        .put(
            &format!("{members}/{bob_id}"),
            &root,
            Some(json!({ "role": "maintainer" })),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = api.get(&format!("/teams/{team}"), &bob).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["permissions"], json!(["manage", "manage_members"]));
    assert_eq!(team_slugs(&api.get("/teams", &bob).await.1), ["platform"]);

    // Bob, a maintainer, adds Dave; Dave, a member, may only look.
    assert_eq!(
        api.put(
            &format!("{members}/{dave_id}"),
            &bob,
            Some(json!({ "role": "member" }))
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        api.get(&format!("/teams/{team}"), &dave).await.1["permissions"],
        json!([])
    );
    assert_eq!(
        api.delete(&format!("{members}/{bob_id}"), &dave).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        member_list(&api, team, &dave).await,
        [
            row("bob (display)", "maintainer", "manual"),
            row("root (display)", "maintainer", "manual"),
            row("dave (display)", "member", "manual"),
        ]
    );
    // Strangers get 404, whatever they try.
    assert_eq!(api.get(&members, &eve).await.0, StatusCode::NOT_FOUND);
    assert_eq!(
        api.delete(&format!("{members}/{dave_id}"), &eve).await.0,
        StatusCode::NOT_FOUND
    );

    // Bob promotes Dave, then removes him.
    api.put(
        &format!("{members}/{dave_id}"),
        &bob,
        Some(json!({ "role": "maintainer" })),
    )
    .await;
    api.put(
        &format!("{members}/{dave_id}"),
        &bob,
        Some(json!({ "role": "maintainer" })),
    )
    .await;
    assert_eq!(
        api.delete(&format!("{members}/{dave_id}"), &bob).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        api.delete(&format!("{members}/{dave_id}"), &bob).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        api.put(
            &format!("{members}/{}", Uuid::new_v4()),
            &bob,
            Some(json!({ "role": "member" }))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );

    let audit: Vec<(String, Value)> =
        sqlx::query!(r#"SELECT action, details::text AS "details!" FROM audit_log ORDER BY id"#)
            .fetch_all(&pool)
            .await
            .unwrap()
            .into_iter()
            .map(|row| (row.action, serde_json::from_str(&row.details).unwrap()))
            .collect();
    assert_eq!(
        audit,
        [
            ("team.created".to_owned(), json!({})),
            (
                "team.member_set".to_owned(),
                json!({ "user_id": bob_id, "role": "maintainer" })
            ),
            (
                "team.member_set".to_owned(),
                json!({ "user_id": dave_id, "role": "member" })
            ),
            (
                "team.member_set".to_owned(),
                json!({ "user_id": dave_id, "role": "maintainer" })
            ),
            (
                "team.member_removed".to_owned(),
                json!({ "user_id": dave_id })
            ),
        ]
    );
}

#[sqlx::test]
async fn maintainers_rename_and_delete_their_team(pool: PgPool) {
    let api = Api::new(pool.clone());
    let root = admin("root");
    let team = api.team(&root, "platform").await;
    api.team(&root, "taken").await;
    let bob = user("bob", &[]);
    let bob_id = api.user_id(&bob).await;
    api.put(
        &format!("/teams/{team}/members/{bob_id}"),
        &root,
        Some(json!({ "role": "maintainer" })),
    )
    .await;
    let uri = format!("/teams/{team}");

    let (status, body) = api
        .patch(&uri, &bob, json!({ "name": "Platform team" }))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], "Platform team");
    assert_eq!(
        api.patch(&uri, &bob, json!({ "slug": "taken" })).await.0,
        StatusCode::CONFLICT
    );
    // The IdP group is for platform admins only.
    assert_eq!(
        api.patch(&uri, &bob, json!({ "idp_group": "platform" }))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        api.patch(&uri, &bob, json!({ "idp_group": null })).await.0,
        StatusCode::FORBIDDEN
    );

    // Deleting the team removes its links.
    let acme = api.organization(&root, "acme").await;
    api.put(
        &format!("/organizations/{acme}/teams/{team}"),
        &root,
        Some(json!({ "access": "write" })),
    )
    .await;
    assert_eq!(api.delete(&uri, &bob).await.0, StatusCode::NO_CONTENT);
    assert_eq!(api.get(&uri, &root).await.0, StatusCode::NOT_FOUND);
    assert_eq!(
        api.get(&format!("/organizations/{acme}/teams"), &root)
            .await
            .1,
        json!([])
    );
}

#[sqlx::test]
async fn synced_teams_take_their_members_from_the_identity_provider(pool: PgPool) {
    let api = Api::new(pool.clone());
    let root = admin("root");
    let root_id = api.user_id(&root).await;
    let team = api.team(&root, "platform").await;
    let uri = format!("/teams/{team}");
    let bob = user("bob", &[]);
    let bob_id = api.user_id(&bob).await;
    api.put(
        &format!("{uri}/members/{bob_id}"),
        &root,
        Some(json!({ "role": "member" })),
    )
    .await;

    // Setting a group replaces the manual members.
    let (status, body) = api
        .patch(&uri, &root, json!({ "idp_group": "platform-team" }))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["idp_group"], "platform-team");
    assert_eq!(body["permissions"], json!(["manage", "set_idp_group"]));
    assert_eq!(member_list(&api, team, &root).await, []);

    // Members join as they make requests with the group.
    let dave = user("dave", &["platform-team"]);
    let dave_id = api.user_id(&dave).await;
    assert_eq!(
        member_list(&api, team, &dave).await,
        [row("dave (display)", "member", "idp")]
    );

    // Their memberships cannot be edited, nor can anyone be added.
    for (method, member) in [
        ("put", dave_id),
        ("delete", dave_id),
        ("put", bob_id),
        ("put", root_id),
    ] {
        let member = format!("{uri}/members/{member}");
        let status = if method == "put" {
            api.put(&member, &root, Some(json!({ "role": "maintainer" })))
                .await
                .0
        } else {
            api.delete(&member, &root).await.0
        };
        assert_eq!(status, StatusCode::CONFLICT, "{method} {member}");
    }

    // The group is unique.
    let other = api.team(&root, "other").await;
    assert_eq!(
        api.patch(
            &format!("/teams/{other}"),
            &root,
            json!({ "idp_group": "platform-team" })
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let (status, body) = api
        .patch(
            &format!("/teams/{other}"),
            &root,
            json!({ "idp_group": "" }),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        body["errors"],
        json!([{ "pointer": "/idp_group", "code": "required" }])
    );

    // A rename leaves the group and its members alone; clearing the group
    // removes the synced members.
    let (status, body) = api.patch(&uri, &root, json!({ "name": "Renamed" })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["idp_group"], "platform-team");
    assert_eq!(member_list(&api, team, &root).await.len(), 1);
    let (status, body) = api.patch(&uri, &root, json!({ "idp_group": null })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["idp_group"], Value::Null);
    assert_eq!(member_list(&api, team, &root).await, []);
    assert_eq!(
        api.put(
            &format!("{uri}/members/{dave_id}"),
            &root,
            Some(json!({ "role": "member" }))
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );

    let fields: Vec<Value> = sqlx::query_scalar!(
        r#"SELECT details::text AS "details!" FROM audit_log WHERE action = 'team.updated' ORDER BY id"#
    )
    .fetch_all(&pool)
    .await
    .unwrap()
    .into_iter()
    .map(|details| serde_json::from_str::<Value>(&details).unwrap()["fields"].clone())
    .collect();
    assert_eq!(
        fields,
        [json!(["idp_group"]), json!(["name"]), json!(["idp_group"])]
    );
}

#[sqlx::test]
async fn organization_admins_see_every_team(pool: PgPool) {
    let api = Api::new(pool);
    let root = admin("root");
    api.team(&root, "b-team").await;
    api.team(&root, "a-team").await;
    let carol = user("carol", &[]);
    let carol_id = api.user_id(&carol).await;
    assert_eq!(api.get("/teams", &carol).await.1, json!([]));
    api.put(
        &format!("/organizations/00000000-0000-0000-0000-000000000001/admins/{carol_id}"),
        &root,
        None,
    )
    .await;
    assert_eq!(
        team_slugs(&api.get("/teams", &carol).await.1),
        ["a-team", "b-team"]
    );
}

#[sqlx::test]
async fn delete_idp_group_stops_syncing(pool: PgPool) {
    let api = Api::new(pool);
    let root = admin("root");
    let team = api.team(&root, "platform").await;
    let uri = format!("/teams/{team}");
    api.patch(&uri, &root, json!({ "idp_group": "platform-team" }))
        .await;
    api.user_id(&user("dave", &["platform-team"])).await;
    assert_eq!(member_list(&api, team, &root).await.len(), 1);

    // A maintainer may not; a platform admin may.
    let bob = user("bob", &[]);
    let bob_id = api.user_id(&bob).await;
    let (status, _) = api.delete(&format!("{uri}/idp_group"), &bob).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, body) = api.delete(&format!("{uri}/idp_group"), &root).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["idp_group"], Value::Null);
    assert_eq!(
        body["permissions"],
        json!(["manage", "manage_members", "set_idp_group"])
    );
    assert_eq!(member_list(&api, team, &root).await, []);
    api.put(
        &format!("{uri}/members/{bob_id}"),
        &root,
        Some(json!({ "role": "maintainer" })),
    )
    .await;
    assert_eq!(
        api.delete(&format!("{uri}/idp_group"), &bob).await.0,
        StatusCode::FORBIDDEN
    );
}

#[sqlx::test]
async fn renaming_and_setting_the_group_needs_both_permissions(pool: PgPool) {
    use kanbot_backend::authz::policies::Policies;
    // Nobody may manage teams, platform admins included; setting the group
    // stays allowed.
    let policies = Policies::with_deployer(
        r#"@id("frozen-teams") forbid (principal, action == Kanbot::Action::"manageTeam", resource);"#,
    )
    .unwrap();
    let api = Api::of(common::app_with_policies(
        pool.clone(),
        std::sync::Arc::new(policies),
    ));
    let root = admin("root");
    let team = insert_team(&pool, "platform", None).await;
    let uri = format!("/teams/{team}");
    for body in [
        json!({ "name": "Renamed", "idp_group": "g" }),
        json!({ "slug": "renamed", "idp_group": "g" }),
        json!({ "name": "Renamed" }),
        json!({}),
    ] {
        assert_eq!(
            api.patch(&uri, &root, body.clone()).await.0,
            StatusCode::FORBIDDEN,
            "{body}"
        );
    }
    let (status, body) = api.patch(&uri, &root, json!({ "idp_group": "g" })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["idp_group"], "g");
}
