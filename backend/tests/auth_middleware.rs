//! The authentication middleware's protections: the failed-authentication
//! limit per client, and the `kanbot.auth.token.rejections` metric.

pub mod common;

use std::num::NonZeroU32;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use common::idp::{access_token, claims, sign};
use kanbot_backend::{
    auth::middleware::AuthMetrics,
    db,
    http::{
        HttpSettings,
        middleware::rate_limit::{RateLimit, RateLimits},
    },
    state::AppState,
};
use opentelemetry::{KeyValue, metrics::MeterProvider};
use opentelemetry_sdk::metrics::{
    InMemoryMetricExporter, PeriodicReader, SdkMeterProvider,
    data::{AggregatedMetrics, MetricData},
};
use serde_json::json;
use sqlx::{PgPool, postgres::PgConnectOptions};
use tower::ServiceExt;

fn unreachable_pool() -> PgPool {
    db::pool_with(
        PgConnectOptions::new_without_pgpass()
            .host("127.0.0.1")
            .port(1),
    )
}

fn app_from(peer: &str, pool: PgPool, settings: HttpSettings) -> Router {
    common::serve_from(
        peer.parse().unwrap(),
        AppState {
            db: pool,
            migrator: &db::MIGRATOR,
            keys: common::idp::static_key_cache(),
            sessions: common::session_config(),
            authz: common::policies(),
        },
        settings,
        None,
    )
}

fn me(authorization: Option<&str>) -> Request<Body> {
    let mut request = Request::get("/me");
    if let Some(authorization) = authorization {
        request = request.header(header::AUTHORIZATION, authorization);
    }
    request.body(Body::empty()).unwrap()
}

async fn status(app: &Router, request: Request<Body>) -> StatusCode {
    app.clone().oneshot(request).await.unwrap().status()
}

fn failures_limited(burst: u32) -> HttpSettings {
    HttpSettings {
        rate_limits: RateLimits {
            auth_failure: RateLimit {
                per_second: NonZeroU32::new(1).unwrap(),
                burst: NonZeroU32::new(burst).unwrap(),
            },
            ..RateLimits::DEFAULT
        },
        ..HttpSettings::new()
    }
}

#[tokio::test]
async fn failed_authentications_are_limited_per_client() {
    let routes = kanbot_backend::http::router(
        AppState {
            db: unreachable_pool(),
            migrator: &db::MIGRATOR,
            keys: common::idp::static_key_cache(),
            sessions: common::session_config(),
            authz: common::policies(),
        },
        failures_limited(2),
        None,
    )
    .unwrap();
    let from = |peer: &str| {
        routes
            .clone()
            .layer(axum::Extension(axum::extract::ConnectInfo(
                peer.parse::<std::net::SocketAddr>().unwrap(),
            )))
    };
    let attacker = from("203.0.113.9:1");

    for _ in 0..2 {
        assert_eq!(
            status(&attacker, me(Some("Bearer forged"))).await,
            StatusCode::UNAUTHORIZED
        );
    }
    // Over budget: any request with credentials is refused before they are
    // checked, even valid ones.
    let valid = format!("Bearer {}", access_token("alice", &["kanbot-user"]));
    let rejected = attacker.clone().oneshot(me(Some(&valid))).await.unwrap();
    assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(rejected.headers()[header::RETRY_AFTER], "1");
    assert_eq!(
        status(&attacker, me(Some("Basic eDp5"))).await,
        StatusCode::TOO_MANY_REQUESTS
    );

    // Requests without credentials are not affected...
    let health = Request::get("/health").body(Body::empty()).unwrap();
    assert_eq!(status(&attacker, health).await, StatusCode::OK);
    assert_eq!(status(&attacker, me(None)).await, StatusCode::UNAUTHORIZED);
    // ...nor are other clients.
    assert_eq!(
        status(&from("198.51.100.7:1"), me(Some("Bearer forged"))).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn unusable_authorization_headers_count_as_failures() {
    let app = app_from(common::PEER, unreachable_pool(), failures_limited(1));
    assert_eq!(
        status(&app, me(Some("Basic eDp5"))).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        status(&app, me(Some("Bearer forged"))).await,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn a_valid_token_without_a_role_is_not_a_failed_authentication() {
    let app = app_from(common::PEER, unreachable_pool(), failures_limited(1));
    let no_role = format!("Bearer {}", access_token("carol", &["staff"]));
    for _ in 0..3 {
        assert_eq!(
            status(&app, me(Some(&no_role))).await,
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        status(&app, me(Some("Bearer forged"))).await,
        StatusCode::UNAUTHORIZED
    );
}

fn meter() -> (SdkMeterProvider, InMemoryMetricExporter) {
    let exporter = InMemoryMetricExporter::default();
    let provider = SdkMeterProvider::builder()
        .with_reader(PeriodicReader::builder(exporter.clone()).build())
        .build();
    (provider, exporter)
}

/// `(reason, count)` of every `kanbot.auth.token.rejections` point.
fn rejections(exporter: &InMemoryMetricExporter) -> Vec<(String, u64)> {
    let mut points = Vec::new();
    for resource in exporter.get_finished_metrics().unwrap() {
        for scope in resource.scope_metrics() {
            for metric in scope
                .metrics()
                .filter(|metric| metric.name() == "kanbot.auth.token.rejections")
            {
                let AggregatedMetrics::U64(MetricData::Sum(sum)) = metric.data() else {
                    panic!("unexpected data: {:?}", metric.data());
                };
                for point in sum.data_points() {
                    let attributes: Vec<KeyValue> = point.attributes().cloned().collect();
                    assert_eq!(attributes.len(), 1, "{attributes:?}");
                    assert_eq!(attributes[0].key.as_str(), "reason");
                    points.push((attributes[0].value.to_string(), point.value()));
                }
            }
        }
    }
    points.sort();
    points
}

#[sqlx::test]
async fn rejections_are_counted_by_reason(pool: PgPool) {
    let (provider, exporter) = meter();
    let app = app_from(
        common::PEER,
        pool.clone(),
        HttpSettings {
            auth_metrics: AuthMetrics::new(&provider.meter("test")),
            ..HttpSettings::new()
        },
    );
    let mut expired = claims("alice", &["kanbot-user"]);
    expired["exp"] = json!(1_000);
    let expired = sign("rsa-a", &expired);
    let unknown_key = sign("rsa-b", &claims("alice", &["kanbot-user"]));
    for authorization in [
        "Bearer forged".to_owned(),
        "Basic eDp5".to_owned(),
        format!("Bearer {expired}"),
        format!("Bearer {unknown_key}"),
        format!("Bearer {}", access_token("carol", &["staff"])),
    ] {
        app.clone().oneshot(me(Some(&authorization))).await.unwrap();
    }
    let dave = format!("Bearer {}", access_token("dave", &["kanbot-user"]));
    assert_eq!(status(&app, me(Some(&dave))).await, StatusCode::OK);
    sqlx::query!("UPDATE users SET disabled_at = now()")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(status(&app, me(Some(&dave))).await, StatusCode::FORBIDDEN);
    provider.force_flush().unwrap();

    assert_eq!(
        rejections(&exporter),
        [
            ("disabled".to_owned(), 1),
            ("expired".to_owned(), 1),
            ("malformed".to_owned(), 2),
            ("no_role".to_owned(), 1),
            ("unknown_key".to_owned(), 1),
        ]
    );
}
