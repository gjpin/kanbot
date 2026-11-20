import 'dart:convert';

/// A failed call to the kanbot backend.
///
/// Messages never contain payloads, headers or tokens (AGENTS.md §2): only
/// the status and the backend's stable error `code`.
sealed class ApiException implements Exception {
  const ApiException();
}

/// The backend answered with a non-`2xx` status.
///
/// The backend sends an RFC 9457 problem details body
/// (`application/problem+json`) with a stable [code], such as `not_found`.
/// [code] is `null` when the body is missing or is not a valid problem (for
/// example an error page from a proxy); the status still decides the type.
sealed class ApiErrorResponse extends ApiException {
  const ApiErrorResponse(this.statusCode, {this.code});

  /// Builds the exception for a response with [statusCode] and [body].
  factory ApiErrorResponse.fromResponse({
    required int statusCode,
    required String? contentType,
    required String body,
  }) {
    final problem = ApiProblem.tryParse(contentType: contentType, body: body);
    final code = problem?.code;
    return switch (statusCode) {
      400 => ApiBadRequestException(code: code),
      401 => ApiUnauthorizedException(code: code),
      403 => ApiForbiddenException(code: code),
      404 => ApiNotFoundException(code: code),
      409 => ApiConflictException(code: code),
      422 => ApiValidationException(
        code: code,
        fieldErrors: problem?.fieldErrors ?? const [],
      ),
      429 => ApiRateLimitedException(code: code),
      503 => ApiUnavailableException(code: code),
      _ => ApiStatusException(statusCode, code: code),
    };
  }

  final int statusCode;

  /// The backend's error code, or `null` without a valid problem body.
  final String? code;

  @override
  String toString() =>
      '$runtimeType: $statusCode${code == null ? '' : ' $code'}';
}

/// `400`: the request is malformed. A client bug: do not retry.
final class ApiBadRequestException extends ApiErrorResponse {
  const ApiBadRequestException({super.code}) : super(400);
}

/// `401`: the token is missing, expired or revoked. Go to the re-auth/logout
/// flow.
final class ApiUnauthorizedException extends ApiErrorResponse {
  const ApiUnauthorizedException({super.code}) : super(401);
}

/// `403`: signed in, but not allowed to do this.
final class ApiForbiddenException extends ApiErrorResponse {
  const ApiForbiddenException({super.code}) : super(403);
}

/// `404`: the resource does not exist (or is not visible to this user).
final class ApiNotFoundException extends ApiErrorResponse {
  const ApiNotFoundException({super.code}) : super(404);
}

/// `409`: the request conflicts with the current state, for example a
/// stale version. Reload, then let the user decide.
final class ApiConflictException extends ApiErrorResponse {
  const ApiConflictException({super.code}) : super(409);
}

/// `422`: one or more fields are invalid. Show [fieldErrors] next to the
/// fields they point at.
final class ApiValidationException extends ApiErrorResponse {
  const ApiValidationException({super.code, this.fieldErrors = const []})
    : super(422);

  final List<ApiFieldError> fieldErrors;
}

/// `429`: too many requests. Safe to retry after a backoff.
final class ApiRateLimitedException extends ApiErrorResponse {
  const ApiRateLimitedException({super.code}) : super(429);
}

/// `503`: the backend is temporarily unavailable (database down, not ready,
/// or request timed out on the server). Safe to retry with backoff.
final class ApiUnavailableException extends ApiErrorResponse {
  const ApiUnavailableException({super.code}) : super(503);
}

/// Any other non-`2xx` status. A `500` is a backend bug: do not retry it
/// automatically.
final class ApiStatusException extends ApiErrorResponse {
  const ApiStatusException(super.statusCode, {super.code});
}

/// The request did not complete within the client's timeout and was aborted.
/// Safe to retry with backoff.
final class ApiTimeoutException extends ApiException {
  const ApiTimeoutException();

  @override
  String toString() => 'ApiTimeoutException';
}

/// The backend could not be reached (no network, DNS failure, connection
/// refused, TLS error).
final class ApiNetworkException extends ApiException {
  const ApiNetworkException();

  @override
  String toString() => 'ApiNetworkException';
}

/// One invalid field of a `422` response.
final class ApiFieldError {
  const ApiFieldError({required this.pointer, required this.code});

  /// JSON Pointer to the field in the request body, for example `/title`.
  final String pointer;

  /// Why it is invalid, for example `too_long`.
  final String code;

  @override
  bool operator ==(Object other) =>
      other is ApiFieldError && other.pointer == pointer && other.code == code;

  @override
  int get hashCode => Object.hash(pointer, code);

  @override
  String toString() => 'ApiFieldError($pointer: $code)';
}

/// The members of a problem details body that clients use.
final class ApiProblem {
  const ApiProblem({required this.code, this.fieldErrors = const []});

  /// Parses a problem details body. Returns `null` unless [contentType] is
  /// `application/problem+json` and [body] is a well-formed problem: an
  /// error response's body is best-effort (a proxy may have written it), so
  /// a malformed one is ignored as a whole rather than half-trusted.
  static ApiProblem? tryParse({
    required String? contentType,
    required String body,
  }) {
    if (contentType == null ||
        !contentType.toLowerCase().startsWith('application/problem+json')) {
      return null;
    }
    final Object? json;
    try {
      json = jsonDecode(body);
    } on FormatException {
      return null;
    }
    if (json case {'code': final String code}) {
      final fieldErrors = _parseFieldErrors(json['errors']);
      return fieldErrors == null
          ? null
          : ApiProblem(code: code, fieldErrors: fieldErrors);
    }
    return null;
  }

  /// `[]` when [errors] is absent, `null` when it is malformed.
  static List<ApiFieldError>? _parseFieldErrors(Object? errors) {
    if (errors == null) return const [];
    if (errors is! List<Object?>) return null;
    final parsed = <ApiFieldError>[];
    for (final error in errors) {
      if (error case {
        'pointer': final String pointer,
        'code': final String code,
      }) {
        parsed.add(ApiFieldError(pointer: pointer, code: code));
      } else {
        return null;
      }
    }
    return parsed;
  }

  final String code;
  final List<ApiFieldError> fieldErrors;
}
