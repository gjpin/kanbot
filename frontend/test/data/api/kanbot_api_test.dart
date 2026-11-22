import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:kanbot/data/api/generated/kanbot_api.dart';
import 'package:kanbot/data/services/api_client.dart';
import 'package:kanbot/data/services/api_exception.dart';
import 'package:kanbot/data/services/token_store.dart';

/// The generated client, wired as in the app: every call goes through
/// [ApiClient].
void main() {
  late List<http.BaseRequest> requests;

  KanbotApi api(http.Response Function(http.BaseRequest) handler) {
    requests = [];
    final client = ApiClient(
      httpClient: MockClient((request) async {
        requests.add(request);
        return handler(request);
      }),
      baseUrl: Uri.parse('https://api.example.com/v1/'),
      tokenStore: TokenStore(),
    );
    return KanbotApi(client, baseUrl: client.baseUrl);
  }

  setUp(() {
    FlutterSecureStorage.setMockInitialValues({
      'auth_token': TokenStore.entry(
        Uri.parse('https://api.example.com/v1/'),
        'abc',
      ),
    });
  });

  test('calls the API below the base URL, with the token', () async {
    final health = await api((_) => http.Response('ok', 200)).health.health();

    expect(health, 'ok');
    expect(requests.single.url, Uri.parse('https://api.example.com/v1/health'));
    expect(requests.single.headers['authorization'], 'Bearer abc');
  });

  test('error responses become typed exceptions', () async {
    final client = api(
      (_) => http.Response(
        '{"type": "urn:kanbot:problem:unavailable", "title": "T", '
        '"status": 503, "code": "unavailable"}',
        503,
        headers: {'content-type': 'application/problem+json'},
      ),
    );

    await expectLater(
      client.health.ready(),
      throwsA(
        isA<ApiUnavailableException>().having(
          (e) => e.code,
          'code',
          'unavailable',
        ),
      ),
    );
  });
}
