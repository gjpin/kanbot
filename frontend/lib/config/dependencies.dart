import 'package:http/http.dart' as http;
import 'package:kanbot/data/api/generated/kanbot_api.dart';
import 'package:kanbot/data/services/api_client.dart';
import 'package:kanbot/data/services/token_store.dart';

/// The app's long-lived services, created once in `main` and handed to the
/// router, which passes them through constructors to the pages and
/// ViewModels that need them.
class AppDependencies {
  AppDependencies({required this.api, required this.tokenStore});

  /// The production services, talking to the API at [apiBaseUrl].
  factory AppDependencies.create({required Uri apiBaseUrl}) {
    final tokenStore = TokenStore();
    return AppDependencies(
      api: apiFor(
        ApiClient(
          httpClient: http.Client(),
          baseUrl: apiBaseUrl,
          tokenStore: tokenStore,
        ),
      ),
      tokenStore: tokenStore,
    );
  }

  /// The generated API client, sending every request through [client].
  static KanbotApi apiFor(ApiClient client) =>
      KanbotApi(client, baseUrl: client.baseUrl);

  /// The backend API, generated from `backend/openapi.json`. Repositories call
  /// it; every request goes through [ApiClient].
  final KanbotApi api;
  final TokenStore tokenStore;
}
