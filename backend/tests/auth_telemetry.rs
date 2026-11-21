//! Authentication never puts tokens or claim values into telemetry: not in
//! spans, logs (at any level) or metrics, for accepted and refused tokens
//! alike.

pub mod common;

use axum::{
    body::Body,
    http::{Request, header},
};
use common::idp::{claims, sign};
use kanbot_backend::{auth::middleware::AuthMetrics, db, http::HttpSettings, state::AppState};
use opentelemetry::{metrics::MeterProvider, trace::TracerProvider as _};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_sdk::{
    logs::{InMemoryLogExporter, SdkLoggerProvider},
    metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider},
    trace::{InMemorySpanExporter, SdkTracerProvider},
};
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;
use tracing_subscriber::layer::SubscriberExt;

/// Claim values that must never be recorded.
const SUBJECT: &str = "subject-6f1c2b";
const NAME: &str = "Name-9d7e41";
const USERNAME: &str = "username-3a8c55";
const GROUP: &str = "group-b42e90";
const CLIENT: &str = "client-77c1d3";

#[sqlx::test]
async fn no_token_or_claim_value_is_recorded(pool: PgPool) {
    let spans = InMemorySpanExporter::default();
    let tracer_provider = SdkTracerProvider::builder()
        .with_simple_exporter(spans.clone())
        .build();
    let logs = InMemoryLogExporter::default();
    let logger_provider = SdkLoggerProvider::builder()
        .with_simple_exporter(logs.clone())
        .build();
    let metrics = InMemoryMetricExporter::default();
    let meter_provider = SdkMeterProvider::builder()
        .with_reader(PeriodicReader::builder(metrics.clone()).build())
        .build();
    // No level filter: debug and trace events are recorded too.
    let subscriber = tracing_subscriber::registry()
        .with(tracing_opentelemetry::layer().with_tracer(tracer_provider.tracer("test")))
        .with(OpenTelemetryTracingBridge::new(&logger_provider));
    let _guard = tracing::subscriber::set_default(subscriber);

    let app = common::serve(
        AppState {
            db: pool,
            migrator: &db::MIGRATOR,
            keys: common::idp::static_key_cache(),
            sessions: common::session_config(),
            authz: common::policies(),
        },
        HttpSettings {
            auth_metrics: AuthMetrics::new(&meter_provider.meter("test")),
            ..HttpSettings::new()
        },
        None,
    );

    let mut user = claims(SUBJECT, &["kanbot-user", GROUP]);
    user["name"] = json!(NAME);
    user["preferred_username"] = json!(USERNAME);
    user["azp"] = json!(CLIENT);
    let mut no_role = user.clone();
    no_role["groups"] = json!([GROUP]);
    let mut expired = user.clone();
    expired["exp"] = json!(1_000);
    let tokens = [
        sign("rsa-a", &user),
        sign("rsa-a", &no_role),
        sign("rsa-a", &expired),
        sign("rsa-b", &user),
    ];
    for token in &tokens {
        for path in ["/me", "/health"] {
            let request = Request::get(path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::COOKIE, "session=cookie-5e2a17")
                .body(Body::empty())
                .unwrap();
            app.clone().oneshot(request).await.unwrap();
        }
    }

    tracer_provider.force_flush().unwrap();
    logger_provider.force_flush().unwrap();
    meter_provider.force_flush().unwrap();
    let recorded = format!(
        "{:?}\n{:?}\n{:?}",
        spans.get_finished_spans().unwrap(),
        logs.get_emitted_logs().unwrap(),
        metrics.get_finished_metrics().unwrap(),
    );
    // The recording is not empty: the requests were seen.
    assert!(
        recorded.contains("kanbot.auth.token.rejections"),
        "{recorded}"
    );
    assert!(recorded.contains("GET /me"), "{recorded}");

    let mut secrets = vec![
        SUBJECT,
        NAME,
        USERNAME,
        GROUP,
        CLIENT,
        "cookie-5e2a17",
        "Bearer",
    ];
    for token in &tokens {
        secrets.push(token);
        secrets.extend(token.split('.'));
    }
    for secret in secrets {
        assert!(!recorded.contains(secret), "recorded: {secret}");
    }
}
