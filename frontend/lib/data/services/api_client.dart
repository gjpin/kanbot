import 'dart:async';

import 'package:dartastic_opentelemetry/dartastic_opentelemetry.dart';
import 'package:http/http.dart' as http;
import 'package:kanbot/config/telemetry.dart';
import 'package:kanbot/data/services/api_exception.dart';
import 'package:kanbot/data/services/token_store.dart';

/// The transport for every call to the kanbot backend (AGENTS.md §3). The
/// generated API client (`KanbotApi`, `lib/data/api/generated/`) sends its
/// requests through it.
///
/// For each request it:
///
/// - refuses any URL outside the API base URL, so the bearer token is only
///   ever sent to the API, and never follows redirects;
/// - adds the bearer token from [TokenStore] at request time (native apps;
///   the web app has no token store, its session is a cookie);
/// - sends `X-Kanbot-CSRF: 1` on state-changing methods, which the backend
///   requires of requests authenticated by the session cookie;
/// - reports a `401` to [onUnauthorized], so the app can sign the user out;
/// - aborts the request when it exceeds [timeout], including reading the
///   response body;
/// - maps non-`2xx` statuses, timeouts and network failures to
///   [ApiException]s, so generated code only ever sees successful responses;
/// - records an OpenTelemetry client span and sends its W3C `traceparent`,
///   so the backend's span joins the same trace.
class ApiClient extends http.BaseClient {
  ApiClient({
    required this._httpClient,
    required Uri baseUrl,
    this._tokenStore,
    this.onUnauthorized,
    this.timeout = defaultTimeout,
  }) : _baseUrl = baseUrl.path.endsWith('/')
           ? baseUrl
           : baseUrl.replace(path: '${baseUrl.path}/');

  static const Duration defaultTimeout = Duration(seconds: 15);

  final http.Client _httpClient;
  final Uri _baseUrl;
  final TokenStore? _tokenStore;

  /// Called when the API answers `401`: the session is gone.
  final void Function()? onUnauthorized;

  /// Methods that change state: they carry the CSRF header.
  static const Set<String> _stateChanging = {'POST', 'PUT', 'PATCH', 'DELETE'};

  /// How long a request may take, including reading the response body.
  final Duration timeout;

  /// The API base URL that every request must stay below, ending with `/`
  /// (so `/v1` never matches `/v1-other`).
  Uri get baseUrl => _baseUrl;

  /// Sends [request] to the API.
  ///
  /// Throws an [ApiException] for any non-`2xx` status, timeout or network
  /// failure, and an [ArgumentError] when the URL is outside the base URL
  /// (another origin, a path above it, encoded separators). Rethrows
  /// [http.RequestAbortedException] when the caller's own abort trigger
  /// fired.
  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    if (!_isBelowBaseUrl(request.url)) {
      throw ArgumentError('request URL must be below the API base URL');
    }
    final abort = Completer<void>();
    if (request case http.Abortable(:final abortTrigger?)) {
      unawaited(
        abortTrigger.whenComplete(() {
          if (!abort.isCompleted) abort.complete();
        }),
      );
    }
    final body = await request.finalize().toBytes();
    final forwarded =
        http.AbortableRequest(
            request.method,
            request.url,
            abortTrigger: abort.future,
          )
          // A redirect could carry the token to another origin.
          ..followRedirects = false
          ..headers.addAll(request.headers)
          ..headers.remove('authorization')
          ..bodyBytes = body;
    if (_stateChanging.contains(request.method.toUpperCase())) {
      forwarded.headers['x-kanbot-csrf'] = '1';
    }
    final token = await _readToken();
    if (token != null) {
      forwarded.headers['authorization'] = 'Bearer $token';
    }

    final span = _startSpan(request);
    OTelAPI.textMapPropagator.inject(
      Context.current.withSpan(span),
      forwarded.headers,
      _HeaderSetter(forwarded.headers),
    );
    try {
      final response = await _httpClient
          .send(forwarded)
          .then(http.Response.fromStream)
          .timeout(timeout);
      span.setIntAttribute('http.response.status_code', response.statusCode);
      if (response.statusCode < 200 || response.statusCode >= 300) {
        _fail(span, '${response.statusCode}');
        if (response.statusCode == 401) onUnauthorized?.call();
        throw ApiErrorResponse.fromResponse(
          statusCode: response.statusCode,
          contentType: response.headers['content-type'],
          body: response.body,
        );
      }
      return http.StreamedResponse(
        http.ByteStream.fromBytes(response.bodyBytes),
        response.statusCode,
        contentLength: response.bodyBytes.length,
        request: request,
        headers: response.headers,
        reasonPhrase: response.reasonPhrase,
      );
    } on TimeoutException {
      _fail(span, 'timeout');
      throw const ApiTimeoutException();
    } on http.RequestAbortedException {
      // Before our timeout fires, only the caller's trigger can abort.
      _fail(span, 'aborted');
      rethrow;
    } on http.ClientException {
      _fail(span, 'network');
      throw const ApiNetworkException();
    } finally {
      span.end();
      // Cancels the underlying request if it is still running (after a
      // timeout). A no-op once the response has been read.
      if (!abort.isCompleted) abort.complete();
    }
  }

  /// A path segment that names a user, organization or team: a UUID.
  static final RegExp _idSegment = RegExp(
    r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$',
  );

  /// [path] with IDs replaced by `:id`, like a route template: which user
  /// or organization a request was about is personal data (AGENTS.md §3a).
  static String templatePath(String path) => path
      .split('/')
      .map((segment) => _idSegment.hasMatch(segment) ? ':id' : segment)
      .join('/');

  /// A client span following the HTTP semantic conventions. The URL is
  /// recorded without its query, which can carry personal data, and with
  /// its IDs as `:id`.
  static APISpan _startSpan(http.BaseRequest request) {
    final url = request.url;
    return OTelAPI.tracer(telemetryScope).startSpan(
      request.method,
      kind: SpanKind.client,
      attributes: OTelAPI.attributesFromMap({
        'http.request.method': request.method,
        'server.address': url.host,
        'server.port': url.port,
        'url.full': Uri(
          scheme: url.scheme,
          host: url.host,
          port: url.port,
          path: templatePath(url.path),
        ).toString(),
      }),
    );
  }

  /// Marks [span] as failed. For client spans, `4xx` is an error too.
  static void _fail(APISpan span, String errorType) {
    span
      ..setStringAttribute<String>('error.type', errorType)
      ..setStatus(SpanStatusCode.Error);
  }

  /// Same origin as the base URL, below its path, and with no segment a
  /// server could decode into a different path (`%2F`, `%5C`). [Uri.parse]
  /// and [Uri.resolve] have already removed `.` and `..` segments, encoded
  /// or not.
  bool _isBelowBaseUrl(Uri url) =>
      url.scheme == _baseUrl.scheme &&
      url.host == _baseUrl.host &&
      url.port == _baseUrl.port &&
      url.userInfo.isEmpty &&
      url.path.startsWith(_baseUrl.path) &&
      !url.pathSegments.any(
        (segment) => segment.contains('/') || segment.contains(r'\'),
      );

  /// The stored token, or `null` when signed out or when secure storage
  /// cannot be read (for example a keychain restored onto another device).
  /// The request then goes out unauthenticated, and a `401` leads the user
  /// through the re-auth flow, which writes a fresh token.
  Future<String?> _readToken() async {
    final store = _tokenStore;
    if (store == null) return null;
    try {
      return await store.read();
    } on Exception {
      return null;
    }
  }

  @override
  void close() => _httpClient.close();
}

/// Writes propagation headers (`traceparent`, `tracestate`) into a request.
final class _HeaderSetter implements TextMapSetter<String> {
  const _HeaderSetter(this._headers);

  final Map<String, String> _headers;

  @override
  void set(String key, String value) => _headers[key] = value;
}
