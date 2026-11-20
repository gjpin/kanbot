//! OpenTelemetry: traces, logs and metrics, exported over OTLP/HTTP
//! (protobuf).
//!
//! Code instruments with `tracing` (spans and events) and the global
//! `opentelemetry` meter. This module installs the subscriber that sends
//! `tracing` spans to the OpenTelemetry tracer (`tracing-opentelemetry`) and events to
//! the OpenTelemetry logger (`opentelemetry-appender-tracing`), plus human-readable
//! logs on stdout.
//!
//! Configuration is the standard `OTEL_*` environment variables, read by the
//! SDK: `OTEL_EXPORTER_OTLP_ENDPOINT` (default `http://localhost:4318`),
//! `OTEL_EXPORTER_OTLP_HEADERS` (may carry credentials: never log it),
//! `OTEL_SERVICE_NAME` (default `kanbot-backend`), `OTEL_RESOURCE_ATTRIBUTES`,
//! `OTEL_TRACES_SAMPLER`, ... `OTEL_SDK_DISABLED=true` turns export off and
//! keeps the stdout logs. `RUST_LOG` filters both (default `info`).

use std::env::VarError;

use opentelemetry::{global, trace::TracerProvider as _};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::{ExporterBuildError, LogExporter, MetricExporter, SpanExporter};
use opentelemetry_sdk::{
    Resource, logs::SdkLoggerProvider, metrics::SdkMeterProvider,
    propagation::TraceContextPropagator, trace::SdkTracerProvider,
};
use tracing_subscriber::{
    EnvFilter, Layer, filter::LevelFilter, filter::Targets, layer::SubscriberExt,
    util::SubscriberInitExt,
};

/// Service name when `OTEL_SERVICE_NAME` is not set.
pub const DEFAULT_SERVICE_NAME: &str = "kanbot-backend";
/// Instrumentation scope of this crate's tracer and meter.
pub const SCOPE: &str = "kanbot-backend";

/// Crates whose own logs must not be exported as OpenTelemetry logs: they run while
/// exporting, so each export would produce more logs to export.
const EXPORT_PIPELINE_TARGETS: [&str; 8] = [
    "opentelemetry",
    "opentelemetry_sdk",
    "opentelemetry_otlp",
    "opentelemetry_http",
    "reqwest",
    "hyper",
    "hyper_util",
    "h2",
];

#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    #[error("invalid OTLP exporter configuration")]
    Exporter(#[from] ExporterBuildError),
    #[error("a global tracing subscriber is already installed")]
    Subscriber(#[from] tracing_subscriber::util::TryInitError),
}

/// The installed OpenTelemetry providers. Call [`Telemetry::shutdown`] before the
/// process exits, outside the async runtime, so buffered telemetry is sent.
#[must_use]
pub struct Telemetry {
    providers: Option<Providers>,
}

struct Providers {
    tracer: SdkTracerProvider,
    meter: SdkMeterProvider,
    logger: SdkLoggerProvider,
}

impl Telemetry {
    /// Installs the global `tracing` subscriber and, unless
    /// `OTEL_SDK_DISABLED=true`, the OpenTelemetry providers, meter and W3C trace
    /// context propagator.
    ///
    /// Must run outside the async runtime: the exporters use a blocking HTTP
    /// client on their own threads.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError`] if an `OTEL_*` variable is invalid or a
    /// subscriber is already installed.
    pub fn init() -> Result<Self, TelemetryError> {
        Self::init_with(std::env::var)
    }

    fn init_with(
        lookup: impl Fn(&'static str) -> Result<String, VarError>,
    ) -> Result<Self, TelemetryError> {
        let stdout = tracing_subscriber::fmt::layer();
        let filter = EnvFilter::builder()
            .with_default_directive(LevelFilter::INFO.into())
            .from_env_lossy();

        if sdk_disabled(&lookup) {
            tracing_subscriber::registry()
                .with(filter)
                .with(stdout)
                .try_init()?;
            return Ok(Self { providers: None });
        }

        let providers = Providers::new(resource(&lookup))?;
        global::set_text_map_propagator(TraceContextPropagator::new());
        global::set_tracer_provider(providers.tracer.clone());
        global::set_meter_provider(providers.meter.clone());

        let traces = tracing_opentelemetry::layer().with_tracer(providers.tracer.tracer(SCOPE));
        let logs = OpenTelemetryTracingBridge::new(&providers.logger).with_filter(
            Targets::new()
                .with_default(LevelFilter::TRACE)
                .with_targets(EXPORT_PIPELINE_TARGETS.map(|target| (target, LevelFilter::OFF))),
        );
        tracing_subscriber::registry()
            .with(filter)
            .with(stdout)
            .with(traces)
            .with(logs)
            .try_init()?;
        Ok(Self {
            providers: Some(providers),
        })
    }

    /// Flushes and stops the exporters. Each provider waits for its pending
    /// export (bounded by the exporter timeout, `OTEL_EXPORTER_OTLP_TIMEOUT`).
    pub fn shutdown(self) {
        let Some(providers) = self.providers else {
            return;
        };
        // The logger goes last so the other providers' failures are exported.
        for (signal, result) in [
            ("traces", providers.tracer.shutdown()),
            ("metrics", providers.meter.shutdown()),
            ("logs", providers.logger.shutdown()),
        ] {
            if let Err(error) = result {
                tracing::warn!(%error, signal, "failed to flush telemetry");
            }
        }
    }
}

impl Providers {
    fn new(resource: Resource) -> Result<Self, ExporterBuildError> {
        Ok(Self {
            tracer: SdkTracerProvider::builder()
                .with_batch_exporter(SpanExporter::builder().with_http().build()?)
                .with_resource(resource.clone())
                .build(),
            meter: SdkMeterProvider::builder()
                .with_periodic_exporter(MetricExporter::builder().with_http().build()?)
                .with_resource(resource.clone())
                .build(),
            logger: SdkLoggerProvider::builder()
                .with_batch_exporter(LogExporter::builder().with_http().build()?)
                .with_resource(resource)
                .build(),
        })
    }
}

/// `OTEL_SDK_DISABLED`: only the exact value `true` (any case) disables the
/// SDK, as the specification requires.
fn sdk_disabled(lookup: &impl Fn(&'static str) -> Result<String, VarError>) -> bool {
    lookup("OTEL_SDK_DISABLED").is_ok_and(|value| value.trim().eq_ignore_ascii_case("true"))
}

/// The SDK's default resource (`OTEL_SERVICE_NAME`,
/// `OTEL_RESOURCE_ATTRIBUTES`, SDK attributes), named `kanbot-backend`
/// unless `OTEL_SERVICE_NAME` says otherwise.
fn resource(lookup: &impl Fn(&'static str) -> Result<String, VarError>) -> Resource {
    let builder = Resource::builder();
    if lookup("OTEL_SERVICE_NAME").is_ok_and(|name| !name.trim().is_empty()) {
        builder.build()
    } else {
        builder.with_service_name(DEFAULT_SERVICE_NAME).build()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use opentelemetry::{Key, Value};

    use super::*;

    fn lookup(vars: &[(&'static str, &str)]) -> impl Fn(&'static str) -> Result<String, VarError> {
        let vars: HashMap<_, _> = vars.iter().map(|(k, v)| (*k, (*v).to_owned())).collect();
        move |name| vars.get(name).cloned().ok_or(VarError::NotPresent)
    }

    #[test]
    fn sdk_is_disabled_only_by_true() {
        for value in ["true", "TRUE", " True "] {
            assert!(
                sdk_disabled(&lookup(&[("OTEL_SDK_DISABLED", value)])),
                "{value}"
            );
        }
        for value in ["false", "1", "yes", ""] {
            assert!(
                !sdk_disabled(&lookup(&[("OTEL_SDK_DISABLED", value)])),
                "{value}"
            );
        }
        assert!(!sdk_disabled(&lookup(&[])));
    }

    #[test]
    fn default_service_name_without_otel_service_name() {
        let resource = resource(&lookup(&[]));
        assert_eq!(
            resource.get(&Key::from_static_str("service.name")),
            Some(Value::from(DEFAULT_SERVICE_NAME))
        );
    }

    #[test]
    fn otel_service_name_is_left_to_the_sdk() {
        // The SDK reads OTEL_SERVICE_NAME from the real environment, which
        // tests must not change; it is enough that ours is not forced.
        let resource = resource(&lookup(&[("OTEL_SERVICE_NAME", "custom")]));
        assert_ne!(
            resource.get(&Key::from_static_str("service.name")),
            Some(Value::from(DEFAULT_SERVICE_NAME))
        );
    }
}
