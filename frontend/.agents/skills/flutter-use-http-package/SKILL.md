---
name: flutter-use-http-package
description: Call the kanbot backend through the generated API client (`KanbotApi`), whose requests go through `ApiClient`. Use when you need to fetch from or send data to the REST API, or add an endpoint.
---
# Calling the Backend

## Contents
- [Setup](#setup)
- [Request Execution & Response Handling](#request-execution--response-handling)
- [Background Parsing](#background-parsing)
- [Workflow: Executing Network Operations](#workflow-executing-network-operations)
- [Examples](#examples)

## Setup

Already done in this project; do not repeat it.

- `http` is a dependency. In `lib/`, only `ApiClient` (`lib/data/services/api_client.dart`), `AppDependencies` (`lib/config/dependencies.dart`, which creates the app's single `http.Client`) and the generated client import it. Tests use `package:http/testing.dart` (`MockClient`).
- Android has the `INTERNET` permission. macOS has `com.apple.security.network.client` in both entitlements files.
- The base URL comes from `--dart-define=API_BASE_URL=...`, validated at startup by `apiBaseUrlFromEnvironment` (`lib/config/api_config.dart`). Release builds must set it, to an `https://` non-loopback URL. Never hardcode a URL.

## Request Execution & Response Handling

*   **Generated client:** the API client in `lib/data/api/generated/` (`KanbotApi`) is generated from the backend's OpenAPI document, `backend/openapi.json`. Repositories get it from `AppDependencies.api`, injected through their constructor, and call `api.<tag>.<operation>(...)`. Never hand-write request or response code for an API endpoint, never call `package:http` directly (top-level `http.get/post/...`, a new `http.Client`), and never edit generated files.
*   **New or changed endpoint:** change the backend first (route with `#[utoipa::path]`, `ToSchema` request/response types), then from `backend/` run `cargo run --bin openapi -- openapi.json`, and from `frontend/` run `dart run tool/generate_api_client.dart`. Commit all of it. CI fails on both sides when the document or the client is stale.
*   **Transport:** every generated request goes through `ApiClient` (`lib/data/services/api_client.dart`), an `http.BaseClient`. Do not add endpoint methods to it. It:
    *   adds `authorization: Bearer <token>` from `TokenStore` at request time. Never set auth headers yourself and never write a token, even a placeholder, in code;
    *   aborts requests after its `timeout`. Do not add your own;
    *   refuses URLs outside the API base URL (`ArgumentError`) and never follows redirects, so the token never leaves the API.
*   **Errors:** any non-`2xx` status, timeout or network failure becomes a sealed `ApiException` (`lib/data/services/api_exception.dart`), thrown before generated code sees the response. Error responses are RFC 9457 problem details; non-`2xx` statuses become `ApiErrorResponse` subtypes carrying `statusCode` and the backend's stable `code` (`null` if the body is not a valid problem):
    *   `ApiBadRequestException` (400): client bug, do not retry.
    *   `ApiUnauthorizedException` (401): go to re-auth/logout.
    *   `ApiForbiddenException` (403), `ApiNotFoundException` (404), `ApiConflictException` (409): show a message for the `code`.
    *   `ApiValidationException` (422): show each of its `fieldErrors` (`pointer`, `code`) next to the field.
    *   `ApiRateLimitedException` (429), `ApiUnavailableException` (503), `ApiTimeoutException`: temporary, safe to retry with backoff.
    *   `ApiStatusException` (anything else, including 500): do not retry automatically.
    *   `ApiNetworkException`: backend unreachable.
    A `switch` over `ApiException` can end with `ApiErrorResponse()` to cover the remaining statuses.
    Never return `null` on failure, and never throw a generic `Exception('Failed')`.
*   **Payloads and models:** generated code encodes request bodies and decodes responses into generated models. Repositories map them to domain models; the UI never sees generated types. A `2xx` response that does not match the schema makes generated code throw (a `TypeError`): that is a contract violation between app and backend, fixed by regenerating, not something to catch (`frontend/AGENTS.md` §5).

## Background Parsing

Generated code decodes on the calling isolate. If a response is large enough to take more than 16 ms to decode, raise it: swagger_parser can decode in a background isolate (`generation.decode_responses_in_background` in `swagger_parser.yaml`).

## Workflow: Executing Network Operations

**Task Progress:**
- [ ] 1. If the endpoint does not exist yet, add it to the backend and regenerate `backend/openapi.json` and the client (see above).
- [ ] 2. Call the generated client from a repository (`lib/data/repositories/`) and map its models to domain models. Test the repository against the real generated client over `MockClient` (see the example), including error paths.
- [ ] 3. The ViewModel calls the repository and exposes an explicit loading/data/error state.
- [ ] 4. In the UI, create the `Future` in `initState` or the ViewModel, never in `build()`.
- [ ] 5. Map errors to user-facing messages. Never render `snapshot.error` or `e.toString()`.
- [ ] 6. Run the checks in `frontend/AGENTS.md` §10.

## Examples

### Repository over the Generated Client

```dart
import 'package:kanbot/data/api/generated/kanbot_api.dart';
import 'package:kanbot/data/services/api_exception.dart';

/// Whether the backend can take traffic. Uses the real `health` client.
class ServerStatusRepository {
  ServerStatusRepository({required this._api});

  final KanbotApi _api;

  /// `false` while the backend reports itself not ready (`503`). Throws any
  /// other `ApiException`.
  Future<bool> isReady() async {
    try {
      await _api.health.ready();
      return true;
    } on ApiUnavailableException {
      return false;
    }
  }
}
```

A feature repository looks the same, with a domain model mapped from the generated one (here a `photos` tag with a `list_photos` operation, for illustration):

```dart
Future<List<Photo>> fetchPhotos() async => [
  for (final photo in await _api.photos.listPhotos())
    Photo(id: photo.id, title: photo.title, thumbnailUrl: photo.thumbnailUrl),
];
```

### Testing the Repository

Run the real generated client and `ApiClient` over `MockClient`: the test then covers the request, decoding and error mapping.

```dart
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:kanbot/config/dependencies.dart';
import 'package:kanbot/data/services/api_client.dart';
import 'package:kanbot/data/services/token_store.dart';

void main() {
  // Signed out: TokenStore reads the in-memory fake storage.
  setUp(() => FlutterSecureStorage.setMockInitialValues({}));

  ServerStatusRepository repository(http.Response response) =>
      ServerStatusRepository(
        api: AppDependencies.apiFor(
          ApiClient(
            httpClient: MockClient((request) async {
              expect(request.url.path, '/ready');
              return response;
            }),
            baseUrl: Uri.parse('https://api.example.com/'),
            tokenStore: TokenStore(),
          ),
        ),
      );

  test('is ready on 200', () async {
    expect(await repository(http.Response('', 200)).isReady(), isTrue);
  });

  test('is not ready on 503', () async {
    expect(await repository(http.Response('', 503)).isReady(), isFalse);
  });
}
```

### UI Integration

`PhotoRepository` holds the `fetchPhotos` above; `Photo` is a plain domain model (`id`, `title`, `thumbnailUrl`).

```dart
import 'package:flutter/widgets.dart';
import 'package:shad/shad.dart';

class PhotoGallery extends StatefulWidget {
  const PhotoGallery({super.key, required this.repository});

  final PhotoRepository repository;

  @override
  State<PhotoGallery> createState() => _PhotoGalleryState();
}

class _PhotoGalleryState extends State<PhotoGallery> {
  // Created once, not in build(), so rebuilds do not refetch.
  late final Future<List<Photo>> _photos = widget.repository.fetchPhotos();

  @override
  Widget build(BuildContext context) {
    return FutureBuilder<List<Photo>>(
      future: _photos,
      builder: (context, snapshot) => switch (snapshot) {
        AsyncSnapshot(hasData: true, :final data?) => ListView.builder(
          itemCount: data.length,
          itemBuilder: (context, index) => PhotoTile(photo: data[index]),
        ),
        // Never show snapshot.error. Report it to crash reporting instead.
        AsyncSnapshot(hasError: true) => const ShadAlert.destructive(
          title: Text('Could not load photos'),
          description: Text('Check your connection and try again.'),
        ),
        _ => const Center(child: ShadSpinner()),
      },
    );
  }
}

class PhotoTile extends StatelessWidget {
  const PhotoTile({super.key, required this.photo});

  final Photo photo;

  @override
  Widget build(BuildContext context) {
    return ShadRow(
      spacing: 3,
      children: [
        Image.network(
          photo.thumbnailUrl,
          width: 48,
          height: 48,
          // Decode at display size, not the full image.
          cacheWidth: 96,
          cacheHeight: 96,
          errorBuilder: (context, error, stackTrace) =>
              const SizedBox(width: 48, height: 48, child: Icon(LucideIcons.imageOff)),
          loadingBuilder: (context, child, progress) =>
              progress == null ? child : const SizedBox(width: 48, height: 48, child: ShadSpinner()),
        ),
        Expanded(child: Text(photo.title)),
      ],
    );
  }
}
```
