import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:kanbot/data/services/api_client.dart';
import 'package:kanbot/data/services/api_exception.dart';
import 'package:kanbot/data/services/token_store.dart';
import 'package:mockito/annotations.dart';
import 'package:mockito/mockito.dart';

import 'api_client_test.mocks.dart';

@GenerateMocks([TokenStore])
void main() {
  final baseUrl = Uri.parse('https://api.example.com/v1/');
  late MockTokenStore tokenStore;

  setUp(() {
    tokenStore = MockTokenStore();
    when(tokenStore.read()).thenAnswer((_) async => null);
  });

  ApiClient client(
    http.Client httpClient, {
    Duration timeout = ApiClient.defaultTimeout,
  }) => ApiClient(
    httpClient: httpClient,
    baseUrl: baseUrl,
    tokenStore: tokenStore,
    timeout: timeout,
  );

  Uri url(String path) => baseUrl.resolve(path);

  MockClient respond(
    int status, [
    String body = '',
    Map<String, String> headers = const {},
  ]) => MockClient((_) async => http.Response(body, status, headers: headers));

  /// Records every request the client forwards.
  (MockClient, List<http.BaseRequest>) recording([int status = 200]) {
    final requests = <http.BaseRequest>[];
    final httpClient = MockClient((request) async {
      requests.add(request);
      return http.Response('', status);
    });
    return (httpClient, requests);
  }

  test('returns 2xx responses with status, headers and body', () async {
    final response = await client(
      respond(201, 'created', {'content-type': 'text/plain'}),
    ).get(url('boards'));

    expect(response.statusCode, 201);
    expect(response.body, 'created');
    expect(response.headers['content-type'], 'text/plain');
    expect((await client(respond(204)).get(url('boards'))).body, '');
  });

  test('forwards method, URL, headers and body', () async {
    final (httpClient, requests) = recording();

    await client(httpClient).post(
      url('boards'),
      headers: {'content-type': 'application/json', 'x-custom': 'yes'},
      body: '{"title":"Todo"}',
    );

    final request = requests.single as http.Request;
    expect(request.method, 'POST');
    expect(request.url, Uri.parse('https://api.example.com/v1/boards'));
    expect(request.headers['content-type'], 'application/json');
    expect(request.headers['x-custom'], 'yes');
    expect(request.body, '{"title":"Todo"}');
  });

  test('never follows redirects', () async {
    final (httpClient, requests) = recording();

    await client(httpClient).get(url('boards'));

    expect(requests.single.followRedirects, isFalse);
  });

  test('maps a redirect to an error instead of following it', () async {
    await expectLater(
      client(respond(302, '', {'location': 'https://evil.example.com/'}))
          .get(url('boards')),
      throwsA(
        isA<ApiStatusException>().having((e) => e.statusCode, 'status', 302),
      ),
    );
  });

  test('refuses URLs outside the base URL, without sending', () async {
    final (httpClient, requests) = recording();
    when(tokenStore.read()).thenAnswer((_) async => 'abc');

    for (final outside in [
      'https://evil.example.com/v1/boards',
      'http://api.example.com/v1/boards',
      'https://api.example.com:8443/v1/boards',
      'https://user@api.example.com/v1/boards',
      'https://api.example.com/admin',
      'https://api.example.com/v1/../admin',
      'https://api.example.com/v1/%2e%2e/admin',
      'https://api.example.com/v1/a%2F..%2Fadmin',
      r'https://api.example.com/v1/a%5C..%5Cadmin',
    ]) {
      await expectLater(
        client(httpClient).get(Uri.parse(outside)),
        throwsArgumentError,
        reason: outside,
      );
    }
    expect(requests, isEmpty);
  });

  test('accepts URLs below the base URL', () async {
    final (httpClient, requests) = recording();

    for (final inside in [
      'https://api.example.com/v1/boards',
      'https://api.example.com/v1/boards/1/cards?limit=10',
      'https://api.example.com/v1/x/../boards',
    ]) {
      await client(httpClient).get(Uri.parse(inside));
    }

    expect(requests.map((r) => r.url.path), [
      '/v1/boards',
      '/v1/boards/1/cards',
      '/v1/boards',
    ]);
  });

  test('sends the stored token as a bearer token', () async {
    when(tokenStore.read()).thenAnswer((_) async => 'abc');
    final (httpClient, requests) = recording();

    await client(httpClient).get(url('boards'));

    expect(requests.single.headers['authorization'], 'Bearer abc');
  });

  test('replaces an authorization header set by the caller', () async {
    when(tokenStore.read()).thenAnswer((_) async => 'abc');
    final (httpClient, requests) = recording();

    await client(httpClient)
        .get(url('boards'), headers: {'Authorization': 'Bearer forged'});

    final sent = requests.single.headers.entries
        .where((header) => header.key.toLowerCase() == 'authorization')
        .map((header) => header.value);
    expect(sent, ['Bearer abc']);
  });

  test('sends no authorization header when signed out', () async {
    final (httpClient, requests) = recording();

    await client(httpClient).get(url('boards'));

    expect(requests.single.headers.containsKey('authorization'), isFalse);
  });

  test('sends no authorization header when secure storage fails', () async {
    when(tokenStore.read())
        .thenAnswer((_) async => throw Exception('keychain unavailable'));
    final (httpClient, requests) = recording();

    final response = await client(httpClient).get(url('boards'));

    expect(response.statusCode, 200);
    expect(requests.single.headers.containsKey('authorization'), isFalse);
  });

  test('maps problem responses to typed exceptions', () async {
    final httpClient = respond(
      422,
      '{"type": "urn:kanbot:problem:validation_failed", "title": "T", '
      '"status": 422, "code": "validation_failed", '
      '"errors": [{"pointer": "/title", "code": "too_long"}]}',
      {'content-type': 'application/problem+json'},
    );

    await expectLater(
      client(httpClient).get(url('boards')),
      throwsA(
        isA<ApiValidationException>()
            .having((e) => e.code, 'code', 'validation_failed')
            .having((e) => e.fieldErrors, 'fieldErrors', const [
              ApiFieldError(pointer: '/title', code: 'too_long'),
            ]),
      ),
    );
  });

  test('maps 401 to ApiUnauthorizedException', () async {
    await expectLater(
      client(respond(401)).get(url('boards')),
      throwsA(isA<ApiUnauthorizedException>()),
    );
  });

  test('maps 503 to ApiUnavailableException', () async {
    await expectLater(
      client(respond(503)).get(url('boards')),
      throwsA(isA<ApiUnavailableException>()),
    );
  });

  test('maps other statuses to ApiStatusException', () async {
    for (final status in [199, 300, 418, 500]) {
      await expectLater(
        client(respond(status)).get(url('boards')),
        throwsA(
          isA<ApiStatusException>().having(
            (e) => e.statusCode,
            'statusCode',
            status,
          ),
        ),
        reason: '$status',
      );
    }
  });

  test('error messages do not contain the response body', () async {
    await expectLater(
      client(respond(500, 'secret detail')).get(url('boards')),
      throwsA(
        isA<ApiException>().having(
          (e) => e.toString(),
          'toString',
          isNot(contains('secret')),
        ),
      ),
    );
  });

  test('maps network failures to ApiNetworkException', () async {
    final httpClient = MockClient(
      (_) async => throw http.ClientException('connection refused'),
    );

    await expectLater(
      client(httpClient).get(url('boards')),
      throwsA(isA<ApiNetworkException>()),
    );
  });

  /// A backend that never answers, and records when it is aborted.
  (MockClient, Completer<void>) hanging() {
    final aborted = Completer<void>();
    // MockClient.streaming receives the original request, including its
    // abort trigger.
    final httpClient = MockClient.streaming((request, _) async {
      if (request case http.Abortable(:final abortTrigger?)) {
        await abortTrigger;
        aborted.complete();
      }
      throw http.RequestAbortedException(request.url);
    });
    return (httpClient, aborted);
  }

  test('aborts a request that exceeds the timeout', () async {
    final (httpClient, aborted) = hanging();

    await expectLater(
      client(
        httpClient,
        timeout: const Duration(milliseconds: 10),
      ).get(url('boards')),
      throwsA(isA<ApiTimeoutException>()),
    );
    await expectLater(aborted.future, completes);
  });

  test("passes the caller's abort through", () async {
    final (httpClient, aborted) = hanging();
    final callerAbort = Completer<void>();
    final request = http.AbortableRequest(
      'GET',
      url('boards'),
      abortTrigger: callerAbort.future,
    );

    final response = client(httpClient).send(request);
    callerAbort.complete();

    await expectLater(response, throwsA(isA<http.RequestAbortedException>()));
    await expectLater(aborted.future, completes);
  });

  test('closes the underlying client', () async {
    var closed = false;
    final inner = _ClosableClient(() => closed = true);

    client(inner).close();

    expect(closed, isTrue);
  });
}

class _ClosableClient extends http.BaseClient {
  _ClosableClient(this._onClose);

  final void Function() _onClose;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) =>
      throw UnimplementedError();

  @override
  void close() => _onClose();
}
