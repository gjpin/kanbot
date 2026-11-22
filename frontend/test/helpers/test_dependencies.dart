import 'dart:async';

import 'package:dartastic_opentelemetry/dartastic_opentelemetry.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:kanbot/config/dependencies.dart';
import 'package:kanbot/config/telemetry.dart';
import 'package:kanbot/data/services/token_store.dart';
import 'package:kanbot/data/services/web_auth.dart';

import 'fake_backend.dart';

/// The server tests talk to.
final Uri testServer = Uri.parse('https://kanbot.example.com/');

/// A [WebAuth] that answers with a scripted redirect, recording the URLs
/// it was asked to open and the callbacks it was to wait for.
class FakeWebAuth implements WebAuth {
  FakeWebAuth(this.answer);

  /// The redirect for the opened URL, now or later; throw to simulate a
  /// cancel.
  FutureOr<Uri> Function(Uri url) answer;
  final List<Uri> opened = [];
  final List<String> callbacks = [];

  @override
  Future<Uri> authenticate({required Uri url, required String callback}) async {
    opened.add(url);
    callbacks.add(callback);
    return answer(url);
  }
}

/// Telemetry exporters that drop everything, even once enabled: tests
/// never send telemetry anywhere.
TelemetryExporters silentTelemetry() => TelemetryExporters(
  create: (_, _) => (spans: SilentExporter(), logs: SilentExporter()),
);

/// Span and log exporters that drop everything.
final class SilentExporter implements SpanExporter, LogRecordExporter {
  @override
  Future<ExportResult> export(List<Object?> items) async =>
      ExportResult.success;

  @override
  Future<void> forceFlush() async {}

  @override
  Future<void> shutdown() async {}
}

/// The app's dependencies (`AppDependencies.create`) over [backend]. A
/// native app by default, connected to [testServer] unless [connected] is
/// false, with secure storage starting from [storage].
AppDependencies testDependencies({
  FakeBackend? backend,
  bool web = false,
  bool connected = true,
  WebAuth? webAuth,
  Map<String, String> storage = const {},
  List<Uri>? navigations,
  TelemetryExporters? telemetry,
  Uri? defaultServer,
  Future<int> Function()? freePort,
}) {
  FlutterSecureStorage.setMockInitialValues(Map.of(storage));
  final server = backend ?? FakeBackend();
  final dependencies = AppDependencies.create(
    web: web,
    release: false,
    telemetry: telemetry ?? silentTelemetry(),
    defaultServer: defaultServer,
    newHttpClient: server.client,
    webAuth:
        webAuth ?? FakeWebAuth((_) => throw const SignInCancelledException()),
    navigate: (url) => navigations?.add(url),
    freePort: freePort ?? () async => 43210,
  );
  if (connected) dependencies.connection.connect(testServer);
  return dependencies;
}

/// [testDependencies] with a signed-in user ([me]'s JSON).
Future<AppDependencies> signedIn(
  FakeBackend backend, {
  Map<String, Object?>? user,
  bool web = false,
}) async {
  backend
    ..on('GET', '/auth/config', authConfig())
    ..on('GET', '/me', user ?? me());
  final dependencies = testDependencies(
    backend: backend,
    web: web,
    storage: web
        ? const {}
        : {'auth_token': TokenStore.entry(testServer, 'kbs_test')},
  );
  await dependencies.auth.refresh();
  return dependencies;
}
