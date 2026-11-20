// Copyright (c) 2025, the Dart project authors. Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

/// Examples of Dart pattern matching for JSON handling:
/// - Polymorphic JSON deserialization (discriminated unions)
/// - Nested JSON validation with optional and omitted keys
library;

/// Represents an API response in a sealed hierarchy.
sealed class ApiResponse {}

/// Successful API response carrying data.
class SuccessResponse implements ApiResponse {
  final Map<String, Object?> data;
  SuccessResponse(this.data);
}

/// Error API response carrying an error message and code.
class ErrorResponse implements ApiResponse {
  final String message;
  final int code;
  ErrorResponse(this.message, this.code);
}

/// Parses a raw JSON map into an [ApiResponse] subtype.
ApiResponse parseApiResponse(Object? json) => switch (json) {
  {'status': 'ok', 'data': Map<String, Object?> data} => SuccessResponse(data),
  {'status': 'error', 'message': String msg, 'code': int code} => ErrorResponse(
    msg,
    code,
  ),
  // Never include the payload in the message: it can contain personal data.
  _ => throw const FormatException(
    'Invalid ApiResponse: unknown status or shape',
  ),
};

/// Validates a nested user payload with both required schema and optional keys.
({String id, String name, String email, String? avatarUrl, String primaryTag})
parseUserPayload(Object? json) {
  if (json case {
    'id': final String id,
    'profile':
        {'name': final String name, 'email': final String email} &&
        final Map<String, Object?> profile,
    'tags': [
      final String primaryTag,
      ...,
    ], // Matches at least 1 element, ignores rest
  }) {
    // Match optional/omitted fields separately from the validated submap.
    // Map patterns check for key existence (containsKey), so an omitted key
    // fails matching even if typed as String?. Use a pattern, not `as`.
    final avatarUrl = switch (profile['avatarUrl']) {
      final String? url => url,
      _ => throw const FormatException('Invalid user: avatarUrl'),
    };
    return (
      id: id,
      name: name,
      email: email,
      avatarUrl: avatarUrl,
      primaryTag: primaryTag,
    );
  } else {
    throw const FormatException('Invalid user: missing or mistyped field');
  }
}
