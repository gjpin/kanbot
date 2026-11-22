//! OpenTelemetry instrumentation of requests: server spans that continue the
//! caller's trace, trace ids in problem bodies, logs correlated with spans,
//! and the HTTP and database pool metrics.

use std::time::Duration;

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
    routing::get,
};
use http_body_util::BodyExt;
use kanbot_backend::{
    db,
    error::AppError,
    http::{
        middleware::telemetry::{HttpMetrics, trace_request},
        with_middleware,
    },
};
use opentelemetry::{
    KeyValue, Value, global,
    trace::{SpanKind, Status, TraceContextExt, TracerProvider as _},
};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_sdk::{
    logs::{InMemoryLogExporter, SdkLoggerProvider},
    metrics::{
        InMemoryMetricExporter, PeriodicReader, SdkMeterProvider,
        data::{AggregatedMetrics, MetricData},
    },
    propagation::TraceContextPropagator,
    trace::{InMemorySpanExporter, SdkTracerProvider, SpanData},
};
use serde_json::Value as Json;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;
use tracing::subscriber::DefaultGuard;
use tracing_subscriber::layer::SubscriberExt;

const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const PARENT_SPAN_ID: &str = "00f067aa0ba902b7";

fn routes() -> Router {
    Router::new()
        .route(
            "/items/{id}",
            get(|| async {
                tracing::info!("looking up the item");
                "item"
            }),
        )
        .route(
            "/broken",
            get(|| async { Err::<(), _>(AppError::Unavailable) }),
        )
        .route(
            "/missing",
            get(|| async { Err::<(), _>(AppError::NotFound) }),
        )
}

/// Records the spans and logs of everything run while the guard lives (on
/// this thread, as `#[tokio::test]` runs on one).
struct Recorder {
    spans: InMemorySpanExporter,
    tracer_provider: SdkTracerProvider,
    logs: InMemoryLogExporter,
    logger_provider: SdkLoggerProvider,
    _guard: DefaultGuard,
}

impl Recorder {
    fn install() -> Self {
        // Global and the same value in every test: safe to set concurrently.
        global::set_text_map_propagator(TraceContextPropagator::new());
        let spans = InMemorySpanExporter::default();
        let tracer_provider = SdkTracerProvider::builder()
            .with_simple_exporter(spans.clone())
            .build();
        let logs = InMemoryLogExporter::default();
        let logger_provider = SdkLoggerProvider::builder()
            .with_simple_exporter(logs.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(tracer_provider.tracer("test")))
            .with(OpenTelemetryTracingBridge::new(&logger_provider));
        let guard = tracing::subscriber::set_default(subscriber);
        Self {
            spans,
            tracer_provider,
            logs,
            logger_provider,
            _guard: guard,
        }
    }

    fn server_span(&self) -> SpanData {
        self.tracer_provider.force_flush().unwrap();
        let spans = self.spans.get_finished_spans().unwrap();
        let mut server = spans
            .into_iter()
            .filter(|span| span.span_kind == SpanKind::Server);
        let span = server.next().expect("a server span");
        assert!(server.next().is_none(), "one server span per request");
        span
    }
}

fn attribute(span: &SpanData, key: &str) -> Option<Value> {
    span.attributes
        .iter()
        .find(|attribute| attribute.key.as_str() == key)
        .map(|attribute| attribute.value.clone())
}

async fn send(request: Request<Body>) -> (StatusCode, Vec<u8>) {
    let response = with_middleware(routes(), &[])
        .oneshot(request)
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, body.to_vec())
}

fn get_request(uri: &str) -> Request<Body> {
    Request::get(uri).body(Body::empty()).unwrap()
}

#[tokio::test]
async fn each_request_gets_a_server_span() {
    let recorder = Recorder::install();

    let (status, _) = send(get_request("/items/42?secret=yes")).await;

    assert_eq!(status, StatusCode::OK);
    let span = recorder.server_span();
    assert_eq!(span.name, "GET /items/{id}");
    assert_eq!(span.status, Status::Unset);
    assert_eq!(attribute(&span, "http.request.method"), Some("GET".into()));
    assert_eq!(attribute(&span, "http.route"), Some("/items/{id}".into()));
    assert_eq!(attribute(&span, "url.path"), Some("/items/42".into()));
    assert_eq!(
        attribute(&span, "http.response.status_code"),
        Some(200_i64.into())
    );
    assert!(
        !span
            .attributes
            .iter()
            .any(|attribute| attribute.value.as_str().contains("secret")),
        "the query string must not be recorded: {:?}",
        span.attributes
    );
}

#[tokio::test]
async fn continues_the_callers_trace() {
    let recorder = Recorder::install();
    let request = Request::get("/items/1")
        .header("traceparent", format!("00-{TRACE_ID}-{PARENT_SPAN_ID}-01"))
        .body(Body::empty())
        .unwrap();

    send(request).await;

    let span = recorder.server_span();
    assert_eq!(span.span_context.trace_id().to_string(), TRACE_ID);
    assert_eq!(span.parent_span_id.to_string(), PARENT_SPAN_ID);
    assert!(span.parent_span_is_remote);
}

#[tokio::test]
async fn starts_a_new_trace_without_traceparent() {
    let recorder = Recorder::install();

    send(get_request("/items/1")).await;

    let span = recorder.server_span();
    assert!(span.span_context.is_valid());
    assert_ne!(span.span_context.trace_id().to_string(), TRACE_ID);
    assert!(!span.parent_span_is_remote);
}

#[tokio::test]
async fn server_errors_mark_the_span_as_failed() {
    let recorder = Recorder::install();

    let (status, _) = send(get_request("/broken")).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let span = recorder.server_span();
    assert!(
        matches!(span.status, Status::Error { .. }),
        "{:?}",
        span.status
    );
    assert_eq!(attribute(&span, "error.type"), Some("503".into()));
}

#[tokio::test]
async fn client_errors_do_not_fail_the_span() {
    let recorder = Recorder::install();

    send(get_request("/missing")).await;

    let span = recorder.server_span();
    assert_eq!(span.status, Status::Unset);
    assert_eq!(attribute(&span, "error.type"), None);
}

#[tokio::test]
async fn unmatched_routes_are_named_by_method_only() {
    let recorder = Recorder::install();

    send(get_request("/nope/123")).await;

    let span = recorder.server_span();
    assert_eq!(span.name, "GET");
    assert_eq!(attribute(&span, "http.route"), None);
}

#[tokio::test]
async fn nonstandard_methods_are_bounded() {
    let recorder = Recorder::install();
    let request = Request::builder()
        .method(Method::from_bytes(b"BREW").unwrap())
        .uri("/items/1")
        .body(Body::empty())
        .unwrap();

    send(request).await;

    let span = recorder.server_span();
    assert_eq!(
        attribute(&span, "http.request.method"),
        Some("_OTHER".into())
    );
    assert_eq!(
        attribute(&span, "http.request.method_original"),
        Some("BREW".into())
    );
}

#[tokio::test]
async fn problems_carry_the_trace_id() {
    let recorder = Recorder::install();
    let request = Request::get("/missing")
        .header("traceparent", format!("00-{TRACE_ID}-{PARENT_SPAN_ID}-01"))
        .body(Body::empty())
        .unwrap();

    let (_, body) = send(request).await;

    let body: Json = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["trace_id"], TRACE_ID);
    assert_eq!(
        recorder.server_span().span_context.trace_id().to_string(),
        TRACE_ID
    );
}

#[tokio::test]
async fn problems_from_middleware_carry_the_trace_id() {
    let recorder = Recorder::install();

    let (status, body) = send(get_request("/nope")).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    let body: Json = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        body["trace_id"],
        recorder.server_span().span_context.trace_id().to_string()
    );
}

#[tokio::test]
async fn problems_have_no_trace_id_without_telemetry() {
    let (_, body) = send(get_request("/missing")).await;

    let body: Json = serde_json::from_slice(&body).unwrap();
    assert_eq!(body.get("trace_id"), None);
}

#[tokio::test]
async fn logs_are_correlated_with_the_request_span() {
    let recorder = Recorder::install();

    send(get_request("/items/1")).await;

    let span = recorder.server_span();
    recorder.logger_provider.force_flush().unwrap();
    let logs = recorder.logs.get_emitted_logs().unwrap();
    let log = logs
        .iter()
        .find(|log| {
            log.record
                .body()
                .is_some_and(|body| format!("{body:?}").contains("looking up the item"))
        })
        .expect("the handler's log");
    let trace = log
        .record
        .trace_context()
        .expect("trace context on the log");
    assert_eq!(trace.trace_id, span.span_context.trace_id());
}

fn meter_provider() -> (SdkMeterProvider, InMemoryMetricExporter) {
    let exporter = InMemoryMetricExporter::default();
    let provider = SdkMeterProvider::builder()
        .with_reader(PeriodicReader::builder(exporter.clone()).build())
        .build();
    (provider, exporter)
}

/// Data points of the metric `name`: `(attributes, value)`, where the value
/// is a histogram's count or a sum's value.
fn points(exporter: &InMemoryMetricExporter, name: &str) -> Vec<(Vec<KeyValue>, i64)> {
    let mut points = Vec::new();
    for resource in exporter.get_finished_metrics().unwrap() {
        for scope in resource.scope_metrics() {
            for metric in scope.metrics().filter(|metric| metric.name() == name) {
                match metric.data() {
                    AggregatedMetrics::F64(MetricData::Histogram(histogram)) => {
                        for point in histogram.data_points() {
                            points.push((
                                point.attributes().cloned().collect(),
                                i64::try_from(point.count()).unwrap(),
                            ));
                        }
                    }
                    AggregatedMetrics::I64(MetricData::Sum(sum)) => {
                        for point in sum.data_points() {
                            points.push((point.attributes().cloned().collect(), point.value()));
                        }
                    }
                    other => panic!("unexpected data for {name}: {other:?}"),
                }
            }
        }
    }
    points
}

fn has(attributes: &[KeyValue], key: &str, value: impl Into<Value>) -> bool {
    let value = value.into();
    attributes
        .iter()
        .any(|attribute| attribute.key.as_str() == key && attribute.value == value)
}

#[tokio::test]
async fn requests_are_measured() {
    let (provider, exporter) = meter_provider();
    let app = routes().layer(axum::middleware::from_fn_with_state(
        HttpMetrics::new(&opentelemetry::metrics::MeterProvider::meter(
            &provider, "test",
        )),
        trace_request,
    ));

    for uri in ["/items/1", "/items/2", "/broken"] {
        app.clone().oneshot(get_request(uri)).await.unwrap();
    }
    provider.force_flush().unwrap();

    let durations = points(&exporter, "http.server.request.duration");
    let ok = durations
        .iter()
        .find(|(attributes, _)| {
            has(attributes, "http.route", "/items/{id}")
                && has(attributes, "http.response.status_code", 200_i64)
                && has(attributes, "http.request.method", "GET")
        })
        .expect("a duration series for GET /items/{id} 200");
    assert_eq!(ok.1, 2);
    let failed = durations
        .iter()
        .find(|(attributes, _)| has(attributes, "http.route", "/broken"))
        .expect("a duration series for /broken");
    assert!(has(&failed.0, "error.type", "503"), "{:?}", failed.0);
    assert!(has(&failed.0, "http.response.status_code", 503_i64));

    let active = points(&exporter, "http.server.active_requests");
    assert_eq!(active.len(), 1, "{active:?}");
    assert_eq!(active[0].1, 0, "all requests finished");
}

#[tokio::test]
async fn a_request_the_client_gave_up_on_is_no_longer_active() {
    let (provider, exporter) = meter_provider();
    let app = Router::new()
        .route("/slow", get(std::future::pending::<&'static str>))
        .layer(axum::middleware::from_fn_with_state(
            HttpMetrics::new(&opentelemetry::metrics::MeterProvider::meter(
                &provider, "test",
            )),
            trace_request,
        ));

    // The server drops a request's future when its client disconnects.
    let request = app.oneshot(get_request("/slow"));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), request)
            .await
            .is_err()
    );
    provider.force_flush().unwrap();

    let active = points(&exporter, "http.server.active_requests");
    assert_eq!(active.len(), 1, "{active:?}");
    assert_eq!(active[0].1, 0, "the dropped request is not active");
}

#[tokio::test]
async fn pool_connections_are_reported_by_state() {
    let (provider, exporter) = meter_provider();
    // Never connects: an empty pool has no idle or used connections.
    let pool = PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(1))
        .connect_lazy("postgres://127.0.0.1:1/none")
        .unwrap();

    db::observe_pool(
        &opentelemetry::metrics::MeterProvider::meter(&provider, "test"),
        pool,
    );
    provider.force_flush().unwrap();

    let counts = points(&exporter, "db.client.connection.count");
    assert_eq!(counts.len(), 2, "{counts:?}");
    for state in ["idle", "used"] {
        let (attributes, value) = counts
            .iter()
            .find(|(attributes, _)| has(attributes, "db.client.connection.state", state))
            .unwrap_or_else(|| panic!("no {state} series: {counts:?}"));
        assert_eq!(*value, 0, "{state}");
        assert!(has(attributes, "db.client.connection.pool.name", "kanbot"));
    }
}

#[sqlx::test]
async fn used_pool_connections_are_counted(pool: sqlx::PgPool) {
    let (provider, exporter) = meter_provider();
    db::observe_pool(
        &opentelemetry::metrics::MeterProvider::meter(&provider, "test"),
        pool.clone(),
    );
    let held = pool.acquire().await.unwrap();

    provider.force_flush().unwrap();

    let counts = points(&exporter, "db.client.connection.count");
    let used = counts
        .iter()
        .find(|(attributes, _)| has(attributes, "db.client.connection.state", "used"))
        .unwrap();
    assert_eq!(used.1, 1);
    drop(held);
}

#[test]
fn the_context_of_a_remote_parent_is_extracted() {
    // Guards the header extractor against a propagator that finds nothing.
    let propagator = TraceContextPropagator::new();
    let mut headers = std::collections::HashMap::new();
    headers.insert(
        "traceparent".to_owned(),
        format!("00-{TRACE_ID}-{PARENT_SPAN_ID}-01"),
    );
    let context = opentelemetry::propagation::TextMapPropagator::extract(&propagator, &headers);
    assert_eq!(
        context.span().span_context().trace_id().to_string(),
        TRACE_ID
    );
}
