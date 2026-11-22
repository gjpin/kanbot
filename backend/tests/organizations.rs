//! Organizations: the schema, and the `/organizations` routes.

pub mod common;

use axum::http::StatusCode;
use common::api::{Api, admin, user};
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

/// The Default organization's fixed ID.
const DEFAULT_ORGANIZATION: Uuid = Uuid::from_u128(1);

#[sqlx::test]
async fn the_default_organization_exists(pool: PgPool) {
    let row = sqlx::query!(
        "SELECT slug, name FROM organizations WHERE id = $1",
        DEFAULT_ORGANIZATION
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.slug, "default");
    assert_eq!(row.name, "Default");
}

#[sqlx::test]
async fn the_schema_refuses_invalid_slugs_and_names(pool: PgPool) {
    let insert = |slug: &str, name: &str| {
        let pool = pool.clone();
        let (slug, name) = (slug.to_owned(), name.to_owned());
        async move {
            sqlx::query!(
                "INSERT INTO organizations (id, slug, name) VALUES ($1, $2, $3)",
                Uuid::new_v4(),
                slug,
                name
            )
            .execute(&pool)
            .await
        }
    };
    for slug in ["", "-a", "a-", "A", "a_b", "a b", &"a".repeat(64)] {
        assert!(insert(slug, "Name").await.is_err(), "{slug:?}");
    }
    assert!(insert("ok", "").await.is_err());
    assert!(insert("ok", &"n".repeat(201)).await.is_err());
    insert("a", "Name").await.unwrap();
    insert(&"a".repeat(63), &"n".repeat(200)).await.unwrap();
    insert("a-1", "Name").await.unwrap();
    assert!(insert("a-1", "Other").await.is_err(), "slugs are unique");
}

#[sqlx::test]
async fn deleting_an_organization_removes_its_links_and_admins(pool: PgPool) {
    let user = Uuid::new_v4();
    let team = Uuid::new_v4();
    let organization = Uuid::new_v4();
    sqlx::query!(
        "INSERT INTO users (id, issuer, subject, platform_role) VALUES ($1, 'https://idp', 's', 'user')",
        user
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query!(
        "INSERT INTO teams (id, slug, name) VALUES ($1, 'team', 'Team')",
        team
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query!(
        "INSERT INTO organizations (id, slug, name) VALUES ($1, 'org', 'Org')",
        organization
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query!(
        "INSERT INTO organization_admins (organization_id, user_id) VALUES ($1, $2)",
        organization,
        user
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query!(
        "INSERT INTO organization_teams (organization_id, team_id, access) VALUES ($1, $2, 'write')",
        organization,
        team
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query!("DELETE FROM organizations WHERE id = $1", organization)
        .execute(&pool)
        .await
        .unwrap();

    let remaining = sqlx::query_scalar!(
        r#"SELECT (SELECT count(*) FROM organization_admins) + (SELECT count(*) FROM organization_teams) AS "count!""#
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(remaining, 0);
    let teams = sqlx::query_scalar!(r#"SELECT count(*) AS "count!" FROM teams"#)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(teams, 1, "the team itself stays");
}

/// The audit log's actions, oldest first.
async fn audit_actions(pool: &PgPool) -> Vec<(String, Vec<String>, Value)> {
    sqlx::query!(
        r#"SELECT action, policy_ids, details::text AS "details!" FROM audit_log ORDER BY id"#
    )
    .fetch_all(pool)
    .await
    .unwrap()
    .into_iter()
    .map(|row| {
        (
            row.action,
            row.policy_ids,
            serde_json::from_str(&row.details).unwrap(),
        )
    })
    .collect()
}

/// The slugs of a page of `GET /organizations`.
fn slugs(page: &Value) -> Vec<&str> {
    page["organizations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["slug"].as_str().unwrap())
        .collect()
}

#[sqlx::test]
async fn platform_admins_create_organizations(pool: PgPool) {
    let api = Api::new(pool.clone());
    let root = admin("root");
    let (status, body) = api
        .post(
            "/organizations",
            &root,
            json!({ "slug": "acme", "name": " Acme Inc. " }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["slug"], "acme");
    assert_eq!(body["name"], "Acme Inc.");
    assert_eq!(
        body["permissions"],
        json!([
            "write",
            "manage",
            "manage_admins",
            "manage_team_links",
            "delete"
        ])
    );
    let (_, list) = api.get("/organizations", &root).await;
    assert_eq!(slugs(&list), ["acme", "default"]);

    assert_eq!(
        audit_actions(&pool).await,
        [(
            "organization.created".to_owned(),
            vec!["builtin.platform-admins".to_owned()],
            json!({})
        )]
    );
}

#[sqlx::test]
async fn organizations_come_a_page_at_a_time(pool: PgPool) {
    let api = Api::new(pool);
    let root = admin("root");
    for slug in ["acme", "zeta"] {
        api.organization(&root, slug).await;
    }
    let (status, page) = api.get("/organizations?limit=2", &root).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(slugs(&page), ["acme", "default"]);
    assert_eq!(page["next"], "default");
    let (_, page) = api.get("/organizations?limit=2&after=default", &root).await;
    assert_eq!(slugs(&page), ["zeta"]);
    assert_eq!(page["next"], Value::Null);

    let (status, body) = api.get("/organizations?after=Not%20a%20slug", &root).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        body["errors"],
        json!([{ "pointer": "/after", "code": "invalid" }])
    );
}

#[sqlx::test]
async fn admins_come_a_page_at_a_time(pool: PgPool) {
    let api = Api::new(pool.clone());
    let root = admin("root");
    // Unnamed users sort last; ties by ID.
    let mut ids = Vec::new();
    for name in [Some("carol"), None, Some("alice"), None, Some("bob")] {
        let id = Uuid::new_v4();
        sqlx::query!(
            "INSERT INTO users (id, issuer, subject, platform_role, display_name)
             VALUES ($1, 'x', $2, 'user', $3)",
            id,
            id.to_string(),
            name
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query!(
            "INSERT INTO organization_admins (organization_id, user_id) VALUES ($1, $2)",
            DEFAULT_ORGANIZATION,
            id
        )
        .execute(&pool)
        .await
        .unwrap();
        ids.push(id);
    }
    let admins = format!("/organizations/{DEFAULT_ORGANIZATION}/admins");
    let mut seen = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let uri = match &after {
            Some(after) => format!("{admins}?limit=2&after={after}"),
            None => format!("{admins}?limit=2"),
        };
        let (status, page) = api.get(&uri, &root).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        let items = page["admins"].as_array().unwrap();
        assert!(items.len() <= 2, "{page}");
        seen.extend(items.iter().map(|admin| admin["display_name"].clone()));
        match page["next"].as_str() {
            // The next page starts after an admin's ID: no name in the URL.
            Some(next) => {
                let last = items.last().unwrap()["id"].as_str().unwrap();
                assert_eq!(next, last);
                after = Some(next.to_owned());
            }
            None => break,
        }
    }
    assert_eq!(
        seen,
        [
            json!("alice"),
            json!("bob"),
            json!("carol"),
            Value::Null,
            Value::Null,
        ]
    );
    let (_, all) = api.get(&format!("{admins}?limit=1000"), &root).await;
    assert_eq!(all["admins"].as_array().unwrap().len(), 5);
    assert_eq!(all["next"], Value::Null);

    for after in ["not-a-cursor", "alice"] {
        let (status, body) = api.get(&format!("{admins}?after={after}"), &root).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{after}");
        assert_eq!(
            body["errors"],
            json!([{ "pointer": "/after", "code": "invalid" }])
        );
    }
}

#[sqlx::test]
async fn team_links_come_a_page_at_a_time(pool: PgPool) {
    let api = Api::new(pool);
    let root = admin("root");
    let links = format!("/organizations/{DEFAULT_ORGANIZATION}/teams");
    for slug in ["zeta", "alpha", "mid"] {
        let team = api.team(&root, slug).await;
        api.put(
            &format!("{links}/{team}"),
            &root,
            Some(json!({ "access": "read" })),
        )
        .await;
    }
    let link_slugs = |page: &Value| -> Vec<String> {
        page["links"]
            .as_array()
            .unwrap()
            .iter()
            .map(|link| link["team"]["slug"].as_str().unwrap().to_owned())
            .collect()
    };
    let (status, page) = api.get(&format!("{links}?limit=2"), &root).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(link_slugs(&page), ["alpha", "mid"]);
    assert_eq!(page["next"], "mid");
    let (_, page) = api.get(&format!("{links}?limit=2&after=mid"), &root).await;
    assert_eq!(link_slugs(&page), ["zeta"]);
    assert_eq!(page["next"], Value::Null);
    let (_, page) = api.get(&format!("{links}?limit=3"), &root).await;
    assert_eq!(link_slugs(&page), ["alpha", "mid", "zeta"]);
    assert_eq!(page["next"], Value::Null);

    let (status, body) = api
        .get(&format!("{links}?after=Not%20a%20slug"), &root)
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        body["errors"],
        json!([{ "pointer": "/after", "code": "invalid" }])
    );
}

#[sqlx::test]
async fn plain_users_cannot_create_or_see_organizations(pool: PgPool) {
    let api = Api::new(pool.clone());
    let bob = user("bob", &[]);
    let (status, body) = api
        .post(
            "/organizations",
            &bob,
            json!({ "slug": "acme", "name": "Acme" }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "forbidden");
    let (status, list) = api.get("/organizations", &bob).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list, json!({ "organizations": [], "next": null }));
    let (status, _) = api
        .get(&format!("/organizations/{DEFAULT_ORGANIZATION}"), &bob)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(audit_actions(&pool).await, []);
}

#[sqlx::test]
async fn organization_fields_are_validated(pool: PgPool) {
    let api = Api::new(pool);
    let root = admin("root");
    let (status, body) = api
        .post(
            "/organizations",
            &root,
            json!({ "slug": "-Bad", "name": "" }),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        body["errors"],
        json!([
            { "pointer": "/slug", "code": "invalid" },
            { "pointer": "/name", "code": "required" }
        ])
    );
    let (status, _) = api
        .post(
            "/organizations",
            &root,
            json!({ "slug": "a", "name": "A", "extra": 1 }),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    api.organization(&root, "acme").await;
    let (status, body) = api
        .post(
            "/organizations",
            &root,
            json!({ "slug": "acme", "name": "Again" }),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "conflict");
}

#[sqlx::test]
async fn team_links_give_read_or_write(pool: PgPool) {
    let api = Api::new(pool.clone());
    let root = admin("root");
    let bob = user("bob", &[]);
    let bob_id = api.user_id(&bob).await;
    let acme = api.organization(&root, "acme").await;
    let team = api.team(&root, "engineering").await;
    let (status, _) = api
        .put(
            &format!("/teams/{team}/members/{bob_id}"),
            &root,
            Some(json!({ "role": "member" })),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let organization = format!("/organizations/{acme}");
    assert_eq!(api.get(&organization, &bob).await.0, StatusCode::NOT_FOUND);

    let link = format!("{organization}/teams/{team}");
    let (status, _) = api
        .put(&link, &root, Some(json!({ "access": "read" })))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = api.get(&organization, &bob).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["permissions"], json!([]));
    assert_eq!(slugs(&api.get("/organizations", &bob).await.1), ["acme"]);

    api.put(&link, &root, Some(json!({ "access": "write" })))
        .await;
    assert_eq!(
        api.get(&organization, &bob).await.1["permissions"],
        json!(["write"])
    );
    let (status, page) = api.get(&format!("{organization}/teams"), &bob).await;
    assert_eq!(status, StatusCode::OK);
    let links = &page["links"];
    assert_eq!(links[0]["team"]["slug"], "engineering");
    assert_eq!(links[0]["access"], "write");

    // A reader may not change the links.
    let (status, _) = api
        .put(&link, &bob, Some(json!({ "access": "read" })))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = api.delete(&link, &root).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(api.delete(&link, &root).await.0, StatusCode::NOT_FOUND);
    assert_eq!(api.get(&organization, &bob).await.0, StatusCode::NOT_FOUND);

    let unknown = format!("{organization}/teams/{}", Uuid::new_v4());
    assert_eq!(
        api.put(&unknown, &root, Some(json!({ "access": "read" })))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let (status, _) = api
        .put(&link, &root, Some(json!({ "access": "admin" })))
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let actions: Vec<(String, Value)> = audit_actions(&pool)
        .await
        .into_iter()
        .filter(|(action, _, _)| action.starts_with("organization.team"))
        .map(|(action, _, details)| (action, details))
        .collect();
    assert_eq!(
        actions,
        [
            (
                "organization.team_linked".to_owned(),
                json!({ "team_id": team, "access": "read" })
            ),
            (
                "organization.team_linked".to_owned(),
                json!({ "team_id": team, "access": "write" })
            ),
            (
                "organization.team_unlinked".to_owned(),
                json!({ "team_id": team })
            ),
        ]
    );
}

#[sqlx::test]
async fn organization_admins_manage_their_organization(pool: PgPool) {
    let api = Api::new(pool.clone());
    let root = admin("root");
    let carol = user("carol", &[]);
    let carol_id = api.user_id(&carol).await;
    let dave = user("dave", &[]);
    let dave_id = api.user_id(&dave).await;
    let acme = api.organization(&root, "acme").await;
    let admins = format!("/organizations/{acme}/admins");

    let (status, _) = api.put(&format!("{admins}/{carol_id}"), &root, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    // Already an admin: no change, no second audit entry.
    api.put(&format!("{admins}/{carol_id}"), &root, None).await;

    let (status, body) = api.get(&format!("/organizations/{acme}"), &carol).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["permissions"],
        json!(["write", "manage", "manage_admins", "manage_team_links"])
    );
    let (status, list) = api.get(&admins, &carol).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        list,
        json!({
            "admins": [{ "id": carol_id, "display_name": "carol (display)", "disabled": false }],
            "next": null,
        })
    );

    // Carol renames it (the slug she sends is the one it has) and adds
    // Dave; Dave removes Carol.
    let (status, body) = api
        .patch(
            &format!("/organizations/{acme}"),
            &carol,
            json!({ "slug": "acme", "name": "ACME" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        (body["slug"].as_str(), body["name"].as_str()),
        (Some("acme"), Some("ACME"))
    );
    assert_eq!(
        api.put(&format!("{admins}/{dave_id}"), &carol, None)
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        api.delete(&format!("{admins}/{carol_id}"), &dave).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        api.delete(&format!("{admins}/{carol_id}"), &dave).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        api.get(&format!("/organizations/{acme}"), &carol).await.0,
        StatusCode::NOT_FOUND
    );

    // Only platform admins delete organizations.
    assert_eq!(
        api.delete(&format!("/organizations/{acme}"), &dave).await.0,
        StatusCode::FORBIDDEN
    );
    let unknown_user = format!("{admins}/{}", Uuid::new_v4());
    assert_eq!(
        api.put(&unknown_user, &dave, None).await.0,
        StatusCode::NOT_FOUND
    );

    let actions: Vec<String> = audit_actions(&pool)
        .await
        .into_iter()
        .map(|(action, _, _)| action)
        .collect();
    assert_eq!(
        actions,
        [
            "organization.created",
            "organization.admin_added",
            "organization.updated",
            "organization.admin_added",
            "organization.admin_removed",
        ]
    );
    let updated = &audit_actions(&pool).await[2];
    assert_eq!(updated.1, ["builtin.organization-admins"]);
    assert_eq!(updated.2, json!({ "fields": ["name"] }));
}

#[sqlx::test]
async fn organization_changes_are_validated(pool: PgPool) {
    let api = Api::new(pool);
    let root = admin("root");
    let acme = api.organization(&root, "acme").await;
    api.organization(&root, "taken").await;
    let uri = format!("/organizations/{acme}");
    let (status, body) = api.patch(&uri, &root, json!({ "slug": "Nope" })).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        body["errors"],
        json!([{ "pointer": "/slug", "code": "invalid" }])
    );
    assert_eq!(
        api.patch(&uri, &root, json!({ "slug": "taken" })).await.0,
        StatusCode::CONFLICT
    );
    let (status, body) = api.patch(&uri, &root, json!({ "slug": "renamed" })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        (body["slug"].as_str(), body["name"].as_str()),
        (Some("renamed"), Some("acme"))
    );
    let missing = format!("/organizations/{}", Uuid::new_v4());
    assert_eq!(
        api.patch(&missing, &root, json!({ "name": "x" })).await.0,
        StatusCode::NOT_FOUND
    );
}

#[sqlx::test]
async fn the_default_organization_cannot_be_deleted(pool: PgPool) {
    let api = Api::new(pool.clone());
    let root = admin("root");
    let default = format!("/organizations/{DEFAULT_ORGANIZATION}");
    let (status, body) = api.get(&default, &root).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["permissions"],
        json!(["write", "manage", "manage_admins", "manage_team_links"])
    );
    let (status, body) = api.delete(&default, &root).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "conflict");
    assert_eq!(api.get(&default, &root).await.0, StatusCode::OK);

    let acme = api.organization(&root, "acme").await;
    assert_eq!(
        api.delete(&format!("/organizations/{acme}"), &root).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        api.delete(&format!("/organizations/{acme}"), &root).await.0,
        StatusCode::NOT_FOUND
    );
    let actions: Vec<String> = audit_actions(&pool)
        .await
        .into_iter()
        .map(|(action, _, _)| action)
        .collect();
    assert_eq!(actions, ["organization.created", "organization.deleted"]);
}

#[sqlx::test]
async fn the_default_organization_keeps_its_slug(pool: PgPool) {
    let api = Api::new(pool.clone());
    let root = admin("root");
    let default = format!("/organizations/{DEFAULT_ORGANIZATION}");
    let (status, _) = api.patch(&default, &root, json!({ "slug": "other" })).await;
    assert_eq!(status, StatusCode::CONFLICT);
    // Its name may change; its own slug is no change.
    let (status, body) = api
        .patch(
            &default,
            &root,
            json!({ "slug": "default", "name": "Everyone" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["name"], "Everyone");
}

#[sqlx::test]
async fn unchanged_values_are_not_recorded(pool: PgPool) {
    let api = Api::new(pool.clone());
    let root = admin("root");
    let acme = api.organization(&root, "acme").await;
    let team = api.team(&root, "platform").await;
    let before = audit_actions(&pool).await.len();
    let (status, _) = api
        .patch(
            &format!("/organizations/{acme}"),
            &root,
            json!({ "slug": "acme" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let link = format!("/organizations/{acme}/teams/{team}");
    api.put(&link, &root, Some(json!({ "access": "read" })))
        .await;
    api.put(&link, &root, Some(json!({ "access": "read" })))
        .await;
    let actions: Vec<String> = audit_actions(&pool)
        .await
        .into_iter()
        .skip(before)
        .map(|(action, _, _)| action)
        .collect();
    assert_eq!(actions, ["organization.team_linked"]);
}

#[sqlx::test]
async fn disabled_admins_are_listed_as_disabled(pool: PgPool) {
    let api = Api::new(pool.clone());
    let root = admin("root");
    let acme = api.organization(&root, "acme").await;
    let bob = api.user_id(&user("bob", &[])).await;
    let admins = format!("/organizations/{acme}/admins");
    api.put(&format!("{admins}/{bob}"), &root, None).await;
    sqlx::query!("UPDATE users SET disabled_at = now() WHERE id = $1", bob)
        .execute(&pool)
        .await
        .unwrap();
    let (_, list) = api.get(&admins, &root).await;
    assert_eq!(list["admins"][0]["disabled"], true, "{list}");
    // Linked teams show no identity provider group to the organization's
    // readers.
    let team = api.team(&root, "platform").await;
    api.patch(
        &format!("/teams/{team}"),
        &root,
        json!({ "idp_group": "eng" }),
    )
    .await;
    api.put(
        &format!("/organizations/{acme}/teams/{team}"),
        &root,
        Some(json!({ "access": "read" })),
    )
    .await;
    let (_, page) = api
        .get(&format!("/organizations/{acme}/teams"), &root)
        .await;
    let links = &page["links"];
    assert_eq!(
        links[0]["team"],
        json!({ "id": team, "slug": "platform", "name": links[0]["team"]["name"] })
    );
}

#[sqlx::test]
async fn disabled_users_cannot_become_admins(pool: PgPool) {
    let api = Api::new(pool.clone());
    let root = admin("root");
    let acme = api.organization(&root, "acme").await;
    let bob = api.user_id(&user("bob", &[])).await;
    sqlx::query!("UPDATE users SET disabled_at = now() WHERE id = $1", bob)
        .execute(&pool)
        .await
        .unwrap();
    let (status, _) = api
        .put(&format!("/organizations/{acme}/admins/{bob}"), &root, None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[sqlx::test]
async fn a_user_disabled_meanwhile_does_not_become_an_admin(pool: PgPool) {
    // Bob is being disabled while root makes him an admin: the addition
    // waits for the disabling and sees it.
    let api = Api::new(pool.clone());
    let root = admin("root");
    let acme = api.organization(&root, "acme").await;
    let bob = api.user_id(&user("bob", &[])).await;
    let mut disabling = pool.begin().await.unwrap();
    sqlx::query!("UPDATE users SET disabled_at = now() WHERE id = $1", bob)
        .execute(&mut *disabling)
        .await
        .unwrap();
    let admin_uri = format!("/organizations/{acme}/admins/{bob}");
    let (status, _) =
        common::commit_when_blocked(&pool, disabling, api.put(&admin_uri, &root, None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let admins = sqlx::query_scalar!(
        r#"SELECT count(*) AS "count!" FROM organization_admins WHERE user_id = $1"#,
        bob
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(admins, 0);
}

#[sqlx::test]
async fn the_last_admin_may_leave(pool: PgPool) {
    // Unlike a team's last maintainer: the organization is then managed by
    // platform admins only.
    let api = Api::new(pool.clone());
    let root = admin("root");
    let acme = api.organization(&root, "acme").await;
    let carol = user("carol", &[]);
    let carol_id = api.user_id(&carol).await;
    let admins = format!("/organizations/{acme}/admins");
    api.put(&format!("{admins}/{carol_id}"), &root, None).await;
    assert_eq!(
        api.delete(&format!("{admins}/{carol_id}"), &carol).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(api.get(&admins, &root).await.1["admins"], json!([]));
    assert_eq!(
        api.patch(
            &format!("/organizations/{acme}"),
            &carol,
            json!({ "name": "Carol's" })
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        api.patch(
            &format!("/organizations/{acme}"),
            &root,
            json!({ "name": "Root's" })
        )
        .await
        .0,
        StatusCode::OK
    );
}

#[sqlx::test]
async fn linking_a_team_records_the_policies_of_both_decisions(pool: PgPool) {
    // manageTeamLinks on the organization and viewTeam on the team both
    // allowed it: the audit entry lists the policies of both.
    let api = Api::new(pool.clone());
    let root = admin("root");
    let acme = api.organization(&root, "acme").await;
    let platform = api.team(&root, "platform").await;
    let web = api.team(&root, "web").await;
    let carol = user("carol", &[]);
    let carol_id = api.user_id(&carol).await;
    api.put(
        &format!("/organizations/{acme}/admins/{carol_id}"),
        &root,
        None,
    )
    .await;
    // Another platform admin, in neither team (root maintains both).
    let ops = admin("ops");
    for (team, token) in [(platform, &carol), (web, &ops)] {
        let (status, _) = api
            .put(
                &format!("/organizations/{acme}/teams/{team}"),
                token,
                Some(json!({ "access": "read" })),
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }
    let links: Vec<Vec<String>> = audit_actions(&pool)
        .await
        .into_iter()
        .filter(|(action, _, _)| action == "organization.team_linked")
        .map(|(_, policy_ids, _)| policy_ids)
        .collect();
    assert_eq!(
        links,
        [
            vec![
                "builtin.organization-admins".to_owned(),
                "builtin.team-viewers".to_owned()
            ],
            // The same policy allowed both: listed once.
            vec!["builtin.platform-admins".to_owned()],
        ]
    );
}

#[sqlx::test]
async fn linking_a_team_needs_to_see_it(pool: PgPool) {
    use kanbot_backend::authz::policies::Policies;
    // Organization admins may see every team, unless a deployer says no:
    // then they cannot probe or link one either.
    let policies = Policies::with_deployer(
        r#"@id("hidden-teams") forbid (principal, action == Kanbot::Action::"viewTeam", resource)
           unless { principal.platformRole == "admin" };"#,
    )
    .unwrap();
    let api = Api::of(common::app_with_policies(
        pool.clone(),
        std::sync::Arc::new(policies),
    ));
    let root = admin("root");
    let acme = api.organization(&root, "acme").await;
    let team = api.team(&root, "platform").await;
    let carol = user("carol", &[]);
    let carol_id = api.user_id(&carol).await;
    api.put(
        &format!("/organizations/{acme}/admins/{carol_id}"),
        &root,
        None,
    )
    .await;
    let (status, _) = api
        .put(
            &format!("/organizations/{acme}/teams/{team}"),
            &carol,
            Some(json!({ "access": "read" })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
