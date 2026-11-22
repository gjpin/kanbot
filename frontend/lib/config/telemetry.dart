import 'package:dartastic_opentelemetry/dartastic_opentelemetry.dart';
import 'package:flutter/foundation.dart';
import 'package:go_router/go_router.dart';

/// Instrumentation scope of the app's own spans and logs.
const String telemetryScope = 'kanbot-app';

/// The app version reported with telemetry, set at build time with
/// `--dart-define=OTEL_SERVICE_VERSION=1.2.3`.
const String serviceVersion = String.fromEnvironment(
  'OTEL_SERVICE_VERSION',
  defaultValue: 'dev',
);

/// Where the app sends telemetry: the API's relay, which forwards it to the
/// collector (AGENTS.md §2: the app never holds collector credentials).
Uri telemetryEndpoint(Uri apiBaseUrl) => apiBaseUrl.resolve('telemetry');

/// Starts OpenTelemetry: traces and logs, batched to [exporters]. Call
/// once, before `runApp`. Nothing leaves the app until
/// [TelemetryExporters.enable] (AGENTS.md §3a: after sign-in and opt-in).
///
/// Platform resource detection is off: it reports host names and similar
/// details that can identify a person. `--dart-define=OTEL_SDK_DISABLED=true`
/// turns telemetry off.
Future<void> initTelemetry(TelemetryExporters exporters) async {
  final spans = BatchSpanProcessor(exporters.spans);
  final logs = BatchLogRecordProcessor(exporters.logs);
  await OTel.initialize(
    serviceName: telemetryScope,
    serviceVersion: serviceVersion,
    detectPlatformResources: false,
    enableMetrics: false,
    resourceAttributes: OTel.attributesFromMap({
      'os.type': defaultTargetPlatform.name,
    }),
    spanProcessor: spans,
    logRecordProcessor: logs,
  );
  // What the processors still hold when export starts was recorded
  // before consent: flushed into the closed gate, so it is dropped.
  exporters.flushBuffered = () async {
    await spans.forceFlush();
    await logs.forceFlush();
  };
}

/// Builds the OTLP/HTTP exporters for the relay at [endpoint], sending
/// [headers] (the session: a bearer token natively, the CSRF header on the
/// web, where the cookie goes along by itself).
typedef OtlpExporterFactory =
    ({SpanExporter spans, LogRecordExporter logs}) Function(
      Uri endpoint,
      Map<String, String> headers,
    );

/// The relay's OTLP/HTTP exporters.
({SpanExporter spans, LogRecordExporter logs}) otlpExporters(
  Uri endpoint,
  Map<String, String> headers,
) => (
  spans: OtlpHttpSpanExporter(
    OtlpHttpExporterConfig(endpoint: endpoint.toString(), headers: headers),
  ),
  logs: OtlpHttpLogRecordExporter(
    OtlpHttpLogRecordExporterConfig(
      endpoint: endpoint.toString(),
      headers: headers,
    ),
  ),
);

/// The exporters the SDK is set up with once. They drop everything until
/// [enable]d, and again after [disable]: telemetry follows the user's
/// consent and session without restarting the SDK.
class TelemetryExporters {
  TelemetryExporters({this._create = otlpExporters});

  final OtlpExporterFactory _create;
  ({SpanExporter spans, LogRecordExporter logs})? _active;

  late final SpanExporter spans = _GatedSpanExporter(this);
  late final LogRecordExporter logs = _GatedLogRecordExporter(this);

  /// Whether telemetry is being sent.
  bool get enabled => _active != null;

  /// Empties the SDK's buffers through the exporters (set by
  /// [initTelemetry]).
  Future<void> Function()? flushBuffered;

  /// Sends from now on to [endpoint] with [headers]. Telemetry recorded
  /// before (still buffered by the SDK) is dropped first: it predates the
  /// user's consent.
  Future<void> enable(Uri endpoint, Map<String, String> headers) async {
    await disable();
    await flushBuffered?.call();
    _active = _create(endpoint, headers);
  }

  /// Drops everything from now on.
  Future<void> disable() async {
    final active = _active;
    _active = null;
    if (active == null) return;
    await active.spans.shutdown();
    await active.logs.shutdown();
  }
}

final class _GatedSpanExporter implements SpanExporter {
  _GatedSpanExporter(this._gate);

  final TelemetryExporters _gate;

  @override
  Future<void> export(List<Span> spans) async =>
      _gate._active?.spans.export(spans);

  @override
  Future<void> forceFlush() async => _gate._active?.spans.forceFlush();

  @override
  Future<void> shutdown() => _gate.disable();
}

final class _GatedLogRecordExporter implements LogRecordExporter {
  _GatedLogRecordExporter(this._gate);

  final TelemetryExporters _gate;

  @override
  Future<ExportResult> export(List<ReadableLogRecord> logRecords) async =>
      await _gate._active?.logs.export(logRecords) ?? ExportResult.success;

  @override
  Future<void> forceFlush() async => _gate._active?.logs.forceFlush();

  @override
  Future<void> shutdown() => _gate.disable();
}

/// Reports uncaught errors (framework and platform) as OpenTelemetry error
/// logs, then lets Flutter handle them as before.
void reportUncaughtErrors() {
  final presentError = FlutterError.onError;
  FlutterError.onError = (details) {
    reportError(details.exception, details.stack);
    presentError?.call(details);
  };
  PlatformDispatcher.instance.onError = (error, stack) {
    reportError(error, stack);
    // Not handled: keep the platform's default behaviour.
    return false;
  };
}

/// Reports [error] as an OpenTelemetry error log, linked to the active
/// span. Only the error's type and stack trace are sent, never its message,
/// which can contain personal data (AGENTS.md §2).
void reportError(Object error, StackTrace? stack) {
  OTelAPI.logger(telemetryScope).emit(
    severityNumber: Severity.ERROR,
    body: 'Uncaught error',
    eventName: 'exception',
    context: Context.current,
    attributes: OTelAPI.attributesFromMap({
      'exception.type': error.runtimeType.toString(),
      'exception.stacktrace': ?stack?.toString(),
    }),
  );
}

/// Reports each navigation as an `app.navigation` log event with the route
/// template (`/boards/:id`), never the actual path, whose parameters can
/// identify a person or a record.
void reportNavigation(GoRouter router) {
  String? last;
  router.routerDelegate.addListener(() {
    final template = router.routerDelegate.currentConfiguration.fullPath;
    if (template == last) return;
    last = template;
    OTelAPI.logger(telemetryScope).emit(
      severityNumber: Severity.INFO,
      body: 'Navigation',
      eventName: 'app.navigation',
      attributes: OTelAPI.attributesFromMap({
        'app.route': template.isEmpty ? '(unmatched)' : template,
      }),
    );
  });
}
