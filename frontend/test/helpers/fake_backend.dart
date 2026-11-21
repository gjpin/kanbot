import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

/// A scripted kanbot server: `METHOD /path` routes answer with JSON. Any
/// other request fails the test, so a test states every call it expects.
class FakeBackend {
  final Map<String, http.Response Function(http.Request)> _routes = {};

  /// Every request received, in order.
  final List<http.Request> requests = [];

  /// Answers `METHOD path` with [body] as JSON (or an empty body for
  /// `null`) and [status]. A problem body for an error status gets
  /// `application/problem+json`.
  void on(String method, String path, Object? body, {int status = 200}) {
    _routes['$method $path'] = (_) => _response(body, status);
  }

  /// Answers `METHOD path` with whatever [handler] returns.
  void handle(
    String method,
    String path,
    http.Response Function(http.Request request) handler,
  ) => _routes['$method $path'] = handler;

  /// The requests to `METHOD path`.
  List<http.Request> sent(String method, String path) => [
    for (final request in requests)
      if (request.method == method && request.url.path == path) request,
  ];

  /// A new client talking to this backend (an `ApiConnection` factory).
  http.Client client() => MockClient((request) async {
    requests.add(request);
    final route = _routes['${request.method} ${request.url.path}'];
    if (route == null) {
      fail('unexpected request: ${request.method} ${request.url.path}');
    }
    return route(request);
  });

  static http.Response _response(Object? body, int status) {
    if (body == null) return http.Response('', status);
    final problem = status >= 400;
    return http.Response(
      jsonEncode(body),
      status,
      headers: {
        'content-type': problem
            ? 'application/problem+json'
            : 'application/json',
      },
    );
  }
}

/// A problem details body with [code] (RFC 9457).
Map<String, Object?> problem(int status, String code, {Object? errors}) => {
  'type': 'about:blank',
  'title': code,
  'status': status,
  'code': code,
  'errors': ?errors,
};

/// `GET /auth/config`.
Map<String, Object?> authConfig({bool telemetryAvailable = true}) => {
  'login_url': 'https://kanbot.example.com/auth/login',
  'telemetry_available': telemetryAvailable,
  'version': '0.1.0',
};

/// `GET /me`.
Map<String, Object?> me({
  String id = '11111111-1111-4111-8111-111111111111',
  String? name = 'Alice',
  String role = 'user',
  bool telemetryOptIn = false,
  List<String> permissions = const [],
}) => {
  'id': id,
  'display_name': name,
  'platform_role': role,
  'telemetry_opt_in': telemetryOptIn,
  'permissions': permissions,
};

const String orgId = '22222222-2222-4222-8222-222222222222';
const String teamId = '33333333-3333-4333-8333-333333333333';
const String bobId = '44444444-4444-4444-8444-444444444444';

Map<String, Object?> organization({
  String id = orgId,
  String name = 'Acme',
  List<String> permissions = const [],
}) => {'id': id, 'slug': 'acme', 'name': name, 'permissions': permissions};

Map<String, Object?> teamSummary({
  String id = teamId,
  String name = 'Platform',
  String? idpGroup,
}) => {'id': id, 'slug': 'platform', 'name': name, 'idp_group': idpGroup};

Map<String, Object?> team({
  String id = teamId,
  String name = 'Platform',
  String? idpGroup,
  List<String> permissions = const [],
}) => {
  ...teamSummary(id: id, name: name, idpGroup: idpGroup),
  'permissions': permissions,
};

Map<String, Object?> user({String id = bobId, String? name = 'Bob'}) => {
  'id': id,
  'display_name': name,
};
