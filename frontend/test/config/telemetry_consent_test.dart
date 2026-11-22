import 'package:dartastic_opentelemetry/dartastic_opentelemetry.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:kanbot/config/dependencies.dart';
import 'package:kanbot/config/telemetry.dart';
import 'package:kanbot/config/telemetry_consent.dart';
import 'package:kanbot/data/services/token_store.dart';

import '../helpers/fake_backend.dart';
import '../helpers/test_dependencies.dart';

/// Exporters that record what reaches them.
class _Recorder implements SpanExporter, LogRecordExporter {
  int exports = 0;
  int flushes = 0;
  int shutdowns = 0;

  @override
  Future<ExportResult> export(List<Object?> items) async {
    exports++;
    return ExportResult.success;
  }

  @override
  Future<void> forceFlush() async => flushes++;

  @override
  Future<void> shutdown() async => shutdowns++;
}

void main() {
  late List<(Uri, Map<String, String>, _Recorder)> created;

  TelemetryExporters exporters() {
    created = [];
    return TelemetryExporters(
      create: (endpoint, headers) {
        final recorder = _Recorder();
        created.add((endpoint, headers, recorder));
        return (spans: recorder, logs: recorder);
      },
    );
  }

  test('exporters drop everything until enabled, and after', () async {
    final gate = exporters();
    expect(await gate.logs.export([]), ExportResult.success);
    await gate.spans.export([]);
    await gate.spans.forceFlush();
    expect(created, isEmpty);
    expect(gate.enabled, isFalse);

    await gate.enable(Uri.parse('https://kanbot.example.com/telemetry'), {
      'x-kanbot-csrf': '1',
    });
    expect(gate.enabled, isTrue);
    await gate.spans.export([]);
    await gate.logs.export([]);
    await gate.logs.forceFlush();
    final recorder = created.single.$3;
    expect((recorder.exports, recorder.flushes), (2, 1));

    await gate.disable();
    expect(recorder.shutdowns, 2, reason: 'spans and logs');
    await gate.spans.export([]);
    expect(recorder.exports, 2);
    expect(gate.enabled, isFalse);

    // Shutting the SDK down turns the gate off too.
    await gate.enable(Uri.parse('https://kanbot.example.com/telemetry'), {});
    await gate.spans.shutdown();
    expect(gate.enabled, isFalse);
  });

  test('what was buffered before consent is dropped', () async {
    final gate = exporters();
    final order = <String>[];
    gate.flushBuffered = () async {
      // Still closed while the SDK empties its buffers.
      order.add('flushed while ${gate.enabled ? 'open' : 'closed'}');
    };
    await gate.enable(Uri.parse('https://kanbot.example.com/telemetry'), {});
    expect(order, ['flushed while closed']);
    expect(gate.enabled, isTrue);
  });

  /// A session for [user], with telemetry consent watching it.
  Future<(TelemetryConsent, TelemetryExporters, AppDependencies)> watch(
    FakeBackend backend, {
    required Map<String, Object?> user,
    bool telemetryAvailable = true,
    bool web = false,
  }) async {
    backend
      ..on(
        'GET',
        '/auth/config',
        authConfig(telemetryAvailable: telemetryAvailable),
      )
      ..on('GET', '/me', user);
    final dependencies = testDependencies(
      backend: backend,
      web: web,
      storage: web ? const {} : const {'auth_token': 'kbs_secret'},
    );
    final gate = exporters();
    final consent = TelemetryConsent(
      auth: dependencies.auth,
      connection: dependencies.connection,
      exporters: gate,
      tokenStore: web ? null : TokenStore(),
    );
    await dependencies.auth.refresh();
    await consent.pending;
    return (consent, gate, dependencies);
  }

  test('sends only for a signed-in user who opted in', () async {
    final (consent, gate, _) = await watch(
      FakeBackend(),
      user: me(telemetryOptIn: true),
    );
    expect(gate.enabled, isTrue);
    final (endpoint, headers, _) = created.single;
    expect(endpoint, Uri.parse('https://kanbot.example.com/telemetry'));
    expect(headers, {
      'x-kanbot-csrf': '1',
      'authorization': 'Bearer kbs_secret',
    });
    consent.dispose();
  });

  test('the web app sends its cookie, not a token', () async {
    final (consent, gate, _) = await watch(
      FakeBackend(),
      user: me(telemetryOptIn: true),
      web: true,
    );
    expect(gate.enabled, isTrue);
    expect(created.single.$2, {'x-kanbot-csrf': '1'});
    consent.dispose();
  });

  test('sends nothing without consent or a relay', () async {
    for (final (user, available) in [
      (me(), true),
      (me(telemetryOptIn: true), false),
    ]) {
      final (consent, gate, _) = await watch(
        FakeBackend(),
        user: user,
        telemetryAvailable: available,
      );
      expect(gate.enabled, isFalse);
      expect(created, isEmpty);
      consent.dispose();
    }
  });

  test('starts on opt-in, stops on opt-out and on sign-out', () async {
    final backend = FakeBackend();
    final (consent, gate, dependencies) = await watch(backend, user: me());
    expect(gate.enabled, isFalse);

    backend.on('PUT', '/me/preferences', me(telemetryOptIn: true));
    await dependencies.auth.setTelemetryOptIn(optIn: true);
    await consent.pending;
    expect(gate.enabled, isTrue);

    backend.on('PUT', '/me/preferences', me());
    await dependencies.auth.setTelemetryOptIn(optIn: false);
    await consent.pending;
    expect(gate.enabled, isFalse);

    backend
      ..on('PUT', '/me/preferences', me(telemetryOptIn: true))
      ..on('POST', '/auth/logout', {'logout_url': null});
    await dependencies.auth.setTelemetryOptIn(optIn: true);
    await consent.pending;
    expect(gate.enabled, isTrue);
    await dependencies.auth.signOut();
    await consent.pending;
    expect(gate.enabled, isFalse);
    consent.dispose();
  });

  test('a failing update sends nothing and does not stop later ones', () async {
    final backend = FakeBackend();
    final (consent, _, dependencies) = await watch(backend, user: me());
    consent.dispose();
    var calls = 0;
    final gate = TelemetryExporters(
      create: (endpoint, headers) {
        calls++;
        if (calls == 1) throw StateError('exporter failed');
        final recorder = _Recorder();
        return (spans: recorder, logs: recorder);
      },
    );
    final watching = TelemetryConsent(
      auth: dependencies.auth,
      connection: dependencies.connection,
      exporters: gate,
      tokenStore: TokenStore(),
    );
    backend.on('PUT', '/me/preferences', me(telemetryOptIn: true));
    await dependencies.auth.setTelemetryOptIn(optIn: true);
    await watching.pending;
    expect(gate.enabled, isFalse, reason: 'the exporter failed');

    // The next change is still applied.
    backend.on('PUT', '/me/preferences', me(telemetryOptIn: true));
    await dependencies.auth.setTelemetryOptIn(optIn: true);
    await watching.pending;
    expect(gate.enabled, isTrue);
    watching.dispose();
  });

  test('a native session without a token sends nothing', () async {
    final backend = FakeBackend();
    final (consent, gate, dependencies) = await watch(
      backend,
      user: me(telemetryOptIn: true),
    );
    expect(gate.enabled, isTrue);
    await TokenStore().clear();
    // The next change finds no session token: nothing may go out.
    backend.on('PUT', '/me/preferences', me(telemetryOptIn: true));
    await dependencies.auth.setTelemetryOptIn(optIn: true);
    await consent.pending;
    expect(gate.enabled, isFalse);
    consent.dispose();
  });
}
