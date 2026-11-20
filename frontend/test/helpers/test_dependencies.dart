import 'package:flutter_test/flutter_test.dart';
import 'package:http/testing.dart';
import 'package:kanbot/config/dependencies.dart';
import 'package:kanbot/data/services/api_client.dart';
import 'package:kanbot/data/services/token_store.dart';

/// Dependencies for widget tests. Any request to the backend fails the test:
/// a test that needs the API stubs it explicitly.
AppDependencies testDependencies() {
  final tokenStore = TokenStore();
  return AppDependencies(
    api: AppDependencies.apiFor(
      ApiClient(
        httpClient: MockClient((request) async => fail('unexpected request')),
        baseUrl: Uri.parse('https://api.example.com/'),
        tokenStore: tokenStore,
      ),
    ),
    tokenStore: tokenStore,
  );
}
