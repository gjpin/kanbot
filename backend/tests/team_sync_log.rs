//! The identity provider group sync logs what it changed, and nothing when nothing did.
//! Its own test binary: tracing caches whether a log line is wanted across
//! threads, so another test hitting the same line without a subscriber
//! could hide it.

pub mod common;

use kanbot_backend::{teams::service, users::model::UserId};
use sqlx::PgPool;
use uuid::Uuid;

fn groups(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

/// The log lines written while `f` runs (on this thread).
async fn logged<F: std::future::Future<Output = ()>>(f: F) -> String {
    use std::sync::{Arc, Mutex};
    #[derive(Clone)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let buffer = Buffer(Arc::new(Mutex::new(Vec::new())));
    let writer = buffer.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    f.await;
    drop(guard);
    String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap()
}

#[sqlx::test]
async fn sync_logs_only_changes(pool: PgPool) {
    let user = UserId::from_uuid(Uuid::new_v4());
    sqlx::query!(
        "INSERT INTO users (id, issuer, subject, platform_role) VALUES ($1, 'https://idp', 'u', 'user')",
        user.as_uuid()
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query!(
        "INSERT INTO teams (id, slug, name, idp_group) VALUES ($1, 'a', 'A', 'a')",
        Uuid::new_v4()
    )
    .execute(&pool)
    .await
    .unwrap();
    let sync = |names: &'static [&'static str]| {
        let pool = pool.clone();
        async move {
            service::sync_idp_groups(&pool, user, &groups(names))
                .await
                .unwrap();
        }
    };
    let added = logged(sync(&["a"])).await;
    assert!(added.contains("team memberships synced"), "{added}");
    assert!(
        added.contains("added=1") && added.contains("removed=0"),
        "{added}"
    );
    let unchanged = logged(sync(&["a"])).await;
    assert!(!unchanged.contains("synced"), "{unchanged}");
    let removed = logged(sync(&[])).await;
    assert!(
        removed.contains("added=0") && removed.contains("removed=1"),
        "{removed}"
    );
}
