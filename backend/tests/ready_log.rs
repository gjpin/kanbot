//! `/ready` logs why it is not ready once per answer, not once per call:
//! it is public. Its own test binary: tracing caches whether a log line is
//! wanted across threads, so another test hitting the same line without a
//! subscriber could hide it.

pub mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

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
async fn missing_keys_are_logged_once_per_answer(pool: sqlx::PgPool) {
    let app = common::app_with_keys(
        pool,
        &kanbot_backend::db::MIGRATOR,
        common::idp::unloaded_key_cache(),
    );
    let log = logged(async {
        for _ in 0..5 {
            let response = app
                .clone()
                .oneshot(Request::get("/ready").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
    })
    .await;
    assert_eq!(
        log.matches("signing keys have not loaded").count(),
        1,
        "{log}"
    );
}
