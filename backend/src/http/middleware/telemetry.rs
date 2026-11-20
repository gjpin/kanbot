//! A server span and HTTP metrics for every request, following the
//! OpenTelemetry HTTP semantic conventions.
//!
//! The span continues the caller's trace when the request carries a W3C
//! `traceparent` header (the app sends one), so a trace runs from the app
//! through the API. Recorded: method, route template, path and status. Never
//! recorded: the query string, headers and bodies.

use std::time::Instant;

use axum::{
    extract::{MatchedPath, Request, State},
    http::{HeaderMap, Method},
    middleware::Next,
    response::Response,
};
use opentelemetry::{
    KeyValue, global,
    metrics::{Histogram, Meter, UpDownCounter},
    propagation::Extractor,
};
use tracing::{Instrument, field::Empty};
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// Bucket boundaries (seconds) the semantic conventions recommend for
/// `http.server.request.duration`.
const DURATION_BUCKETS: [f64; 14] = [
    0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0,
];

/// The HTTP server instruments.
#[derive(Clone)]
pub struct HttpMetrics {
    duration: Histogram<f64>,
    active: UpDownCounter<i64>,
}

impl HttpMetrics {
    /// Creates the instruments on the global meter. Call after telemetry is
    /// initialized (instruments from the default no-op meter stay no-ops).
    #[must_use]
    pub fn global() -> Self {
        Self::new(&global::meter(crate::telemetry::SCOPE))
    }

    #[must_use]
    pub fn new(meter: &Meter) -> Self {
        Self {
            duration: meter
                .f64_histogram("http.server.request.duration")
                .with_unit("s")
                .with_description("Duration of HTTP server requests.")
                .with_boundaries(DURATION_BUCKETS.to_vec())
                .build(),
            active: meter
                .i64_up_down_counter("http.server.active_requests")
                .with_unit("{request}")
                .with_description("Number of active HTTP server requests.")
                .build(),
        }
    }
}

/// Middleware (`axum::middleware::from_fn_with_state`). Must be the
/// outermost layer, so the span covers every other middleware and sees the
/// final status. Layers added with `Router::layer` run after routing, so
/// `MatchedPath` (the route template) is available here.
pub async fn trace_request(
    State(metrics): State<HttpMetrics>,
    request: Request,
    next: Next,
) -> Response {
    let method = KnownMethod::of(request.method());
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|path| path.as_str().to_owned());
    let name = match &route {
        Some(route) => format!("{} {route}", method.name()),
        None => method.name().to_owned(),
    };
    let span = tracing::info_span!(
        "HTTP request",
        otel.name = name,
        otel.kind = "server",
        otel.status_code = Empty,
        http.request.method = method.name(),
        http.request.method_original = method.original(),
        http.route = route.as_deref(),
        url.path = request.uri().path(),
        http.response.status_code = Empty,
        error.type = Empty,
    );
    let parent = global::get_text_map_propagator(|propagator| {
        propagator.extract(&HeaderExtractor(request.headers()))
    });
    if let Err(error) = span.set_parent(parent) {
        // Only when no OTel layer is installed (export disabled).
        tracing::trace!(%error, "request span has no OTel context");
    }

    let mut attributes = vec![KeyValue::new("http.request.method", method.name())];
    metrics.active.add(1, &attributes);
    let start = Instant::now();
    let response = next.run(request).instrument(span.clone()).await;
    metrics.active.add(-1, &attributes);

    let status = response.status();
    // As i64: OpenTelemetry has no unsigned type, and tracing-opentelemetry
    // records u64 values as strings.
    span.record("http.response.status_code", i64::from(status.as_u16()));
    attributes.push(KeyValue::new(
        "http.response.status_code",
        i64::from(status.as_u16()),
    ));
    if let Some(route) = route {
        attributes.push(KeyValue::new("http.route", route));
    }
    // Server spans: only 5xx is an error (4xx is the client's).
    if status.is_server_error() {
        span.record("otel.status_code", "ERROR");
        span.record("error.type", status.as_str());
        attributes.push(KeyValue::new("error.type", status.as_str().to_owned()));
    }
    metrics
        .duration
        .record(start.elapsed().as_secs_f64(), &attributes);
    response
}

/// A request method, bounded for attributes: methods outside the HTTP
/// standard are recorded as `_OTHER` (with the original on the span only),
/// so clients cannot create unbounded metric series.
enum KnownMethod {
    Standard(&'static str),
    Other(String),
}

impl KnownMethod {
    fn of(method: &Method) -> Self {
        match *method {
            Method::GET => Self::Standard("GET"),
            Method::HEAD => Self::Standard("HEAD"),
            Method::POST => Self::Standard("POST"),
            Method::PUT => Self::Standard("PUT"),
            Method::DELETE => Self::Standard("DELETE"),
            Method::CONNECT => Self::Standard("CONNECT"),
            Method::OPTIONS => Self::Standard("OPTIONS"),
            Method::TRACE => Self::Standard("TRACE"),
            Method::PATCH => Self::Standard("PATCH"),
            ref other => Self::Other(other.as_str().to_owned()),
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Standard(name) => name,
            Self::Other(_) => "_OTHER",
        }
    }

    fn original(&self) -> Option<&str> {
        match self {
            Self::Standard(_) => None,
            Self::Other(original) => Some(original),
        }
    }
}

/// Reads propagation headers (`traceparent`, `tracestate`) for the global
/// propagator.
struct HeaderExtractor<'a>(&'a HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|value| value.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(axum::http::HeaderName::as_str).collect()
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn extractor_reads_headers_by_name() {
        let mut headers = HeaderMap::new();
        headers.insert("traceparent", HeaderValue::from_static("00-abc-def-01"));
        headers.insert("tracestate", HeaderValue::from_static("k=v"));
        let extractor = HeaderExtractor(&headers);

        assert_eq!(extractor.get("traceparent"), Some("00-abc-def-01"));
        assert_eq!(extractor.get("baggage"), None);
        let mut keys = extractor.keys();
        keys.sort_unstable();
        assert_eq!(keys, ["traceparent", "tracestate"]);
    }
}
