//! Organizations: the schema, and the `/organizations` routes.

pub mod common;

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
