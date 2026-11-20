import 'package:dartastic_opentelemetry/dartastic_opentelemetry.dart';
import 'package:dartastic_opentelemetry/testing.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:kanbot/data/services/api_client.dart';
import 'package:kanbot/data/services/api_exception.dart';
import 'package:kanbot/data/services/token_store.dart';

/// `ApiClient`'s OpenTelemetry client spans, recorded by the SDK's
/// in-memory test harness.
void main() {
  late TestHarness harness;

  setUpAll(() async {
    harness = await maybeInitializeOtelForTest(serviceName: 'kanbot-app');
  });

  setUp(() {
    harness.clear();
    FlutterSecureStorage.setMockInitialValues({});
  });

  ApiClient client(MockClient httpClient) => ApiClient(
    httpClient: httpClient,
    baseUrl: Uri.parse('https://api.example.com/v1/'),
    tokenStore: TokenStore(),
  );

  Span onlySpan() {
    final spans = harness.spans.spans;
    expect(spans, hasLength(1));
    return spans.single;
  }

  test('records a client span per request', () async {
    await client(MockClient((_) async => http.Response('ok', 200)))
        .get(Uri.parse('https://api.example.com/v1/boards/1?secret=yes'));

    final span = onlySpan();
    expect(span.name, 'GET');
    expect(span.kind, SpanKind.client);
    expect(span.status, isNot(SpanStatusCode.Error));
    expect(span.attributes.getString('http.request.method'), 'GET');
    expect(span.attributes.getString('server.address'), 'api.example.com');
    expect(span.attributes.getInt('server.port'), 443);
    expect(
      span.attributes.getString('url.full'),
      'https://api.example.com/v1/boards/1',
    );
    expect(span.attributes.getInt('http.response.status_code'), 200);
  });

  test('sends the span as the traceparent of the request', () async {
    final sent = <Map<String, String>>[];

    await client(
      MockClient((request) async {
        sent.add(request.headers);
        return http.Response('', 200);
      }),
    ).get(Uri.parse('https://api.example.com/v1/boards'));

    final span = onlySpan();
    final traceparent = sent.single['traceparent'];
    expect(
      traceparent,
      '00-${span.spanContext.traceId.hexString}-'
      '${span.spanContext.spanId.hexString}-01',
    );
  });

  test('marks error statuses as failed', () async {
    for (final status in [404, 503]) {
      harness.clear();
      await expectLater(
        client(MockClient((_) async => http.Response('', status)))
            .get(Uri.parse('https://api.example.com/v1/boards')),
        throwsA(isA<ApiErrorResponse>()),
      );

      final span = onlySpan();
      expect(span.status, SpanStatusCode.Error, reason: '$status');
      expect(span.attributes.getString('error.type'), '$status');
      expect(span.attributes.getInt('http.response.status_code'), status);
    }
  });

  test('marks network failures as failed', () async {
    await expectLater(
      client(MockClient((_) async => throw http.ClientException('refused')))
          .get(Uri.parse('https://api.example.com/v1/boards')),
      throwsA(isA<ApiNetworkException>()),
    );

    final span = onlySpan();
    expect(span.status, SpanStatusCode.Error);
    expect(span.attributes.getString('error.type'), 'network');
  });

  test('records no span for refused URLs', () async {
    await expectLater(
      client(MockClient((_) async => http.Response('', 200)))
          .get(Uri.parse('https://evil.example.com/')),
      throwsArgumentError,
    );

    expect(harness.spans.spans, isEmpty);
  });
}
