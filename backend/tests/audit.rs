//! The audit log: `GET /audit`.

pub mod common;

use axum::http::StatusCode;
use common::api::{Api, admin, user};
use serde_json::{Value, json};
use sqlx::PgPool;

#[sqlx::test]
async fn platform_admins_read_the_audit_log_newest_first(pool: PgPool) {
    let api = Api::new(pool);
    let root = admin("root");
    let root_id = api.user_id(&root).await;
    let mut created = Vec::new();
    for slug in ["a", "b", "c"] {
        created.push(api.organization(&root, slug).await);
    }

    let (status, page) = api.get("/audit", &root).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["next_before"], Value::Null);
    let entries = page["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 3);
    let newest = &entries[0];
    assert_eq!(newest["action"], "organization.created");
    assert_eq!(newest["target_type"], "organization");
    assert_eq!(newest["target_id"], json!(created[2]));
    assert_eq!(
        newest["actor"],
        json!({ "id": root_id, "display_name": "root (display)", "disabled": false })
    );
    assert_eq!(newest["policy_ids"], json!(["builtin.platform-admins"]));
    assert_eq!(newest["details"], json!({}));
    assert!(newest["at"].as_str().unwrap().ends_with('Z'));

    // Pages of two.
    let (_, first) = api.get("/audit?limit=2", &root).await;
    let ids: Vec<i64> = first["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["id"].as_i64().unwrap())
        .collect();
    assert_eq!(ids.len(), 2);
    assert!(ids[0] > ids[1]);
    assert_eq!(first["next_before"], json!(ids[1]));
    let (_, second) = api
        .get(&format!("/audit?limit=2&before={}", ids[1]), &root)
        .await;
    assert_eq!(second["entries"].as_array().unwrap().len(), 1);
    assert_eq!(second["entries"][0]["target_id"], json!(created[0]));
    assert_eq!(second["next_before"], Value::Null);

    // A page that ends exactly at the last entry says there is no more.
    let (_, exact) = api.get("/audit?limit=3", &root).await;
    assert_eq!(exact["entries"].as_array().unwrap().len(), 3);
    assert_eq!(exact["next_before"], Value::Null);

    // Out-of-range limits are clamped.
    let (_, one) = api.get("/audit?limit=0", &root).await;
    assert_eq!(one["entries"].as_array().unwrap().len(), 1);
    assert_eq!(one["next_before"], one["entries"][0]["id"]);
    let (_, all) = api.get("/audit?limit=1000", &root).await;
    assert_eq!(all["entries"].as_array().unwrap().len(), 3);
    assert_eq!(
        api.get("/audit?limit=x", &root).await.0,
        StatusCode::BAD_REQUEST
    );
}

#[sqlx::test]
async fn only_platform_admins_read_the_audit_log(pool: PgPool) {
    let api = Api::new(pool);
    let root = admin("root");
    let carol = user("carol", &[]);
    let carol_id = api.user_id(&carol).await;
    api.put(
        &format!("/organizations/00000000-0000-0000-0000-000000000001/admins/{carol_id}"),
        &root,
        None,
    )
    .await;
    for token in [carol, user("bob", &[])] {
        let (status, body) = api.get("/audit", &token).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["code"], "forbidden");
    }
}
