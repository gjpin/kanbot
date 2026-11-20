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

/// Starts OpenTelemetry: traces and logs, exported over OTLP/HTTP to the
/// API's relay ([telemetryEndpoint]). Call once, before `runApp`.
///
/// Platform resource detection is off: it reports host names and similar
/// details that can identify a person. `--dart-define=OTEL_SDK_DISABLED=true`
/// turns telemetry off.
Future<void> initTelemetry({required Uri apiBaseUrl}) async {
  final endpoint = telemetryEndpoint(apiBaseUrl).toString();
  await OTel.initialize(
    serviceName: telemetryScope,
    serviceVersion: serviceVersion,
    detectPlatformResources: false,
    enableMetrics: false,
    resourceAttributes: OTel.attributesFromMap({
      'os.type': defaultTargetPlatform.name,
    }),
    spanProcessor: BatchSpanProcessor(
      OtlpHttpSpanExporter(OtlpHttpExporterConfig(endpoint: endpoint)),
    ),
    logRecordProcessor: BatchLogRecordProcessor(
      OtlpHttpLogRecordExporter(
        OtlpHttpLogRecordExporterConfig(endpoint: endpoint),
      ),
    ),
  );
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
