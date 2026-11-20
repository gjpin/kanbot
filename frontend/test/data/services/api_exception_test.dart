import 'package:flutter_test/flutter_test.dart';
import 'package:kanbot/data/services/api_exception.dart';

const problemJson = 'application/problem+json';

String problemBody(String code, {String errors = ''}) =>
    '{"type": "urn:kanbot:problem:$code", "title": "T", "status": 400, '
    '"code": "$code"${errors.isEmpty ? '' : ', "errors": $errors'}}';

void main() {
  group('ApiProblem.tryParse', () {
    test('reads the code', () {
      final problem = ApiProblem.tryParse(
        contentType: problemJson,
        body: problemBody('not_found'),
      );
      expect(problem?.code, 'not_found');
      expect(problem?.fieldErrors, isEmpty);
    });

    test('reads field errors', () {
      final problem = ApiProblem.tryParse(
        contentType: '$problemJson; charset=utf-8',
        body: problemBody(
          'validation_failed',
          errors:
              '[{"pointer": "/title", "code": "too_long"}, '
              '{"pointer": "/labels/2", "code": "required"}]',
        ),
      );
      expect(problem?.fieldErrors, const [
        ApiFieldError(pointer: '/title', code: 'too_long'),
        ApiFieldError(pointer: '/labels/2', code: 'required'),
      ]);
    });

    test('ignores bodies that are not problem details', () {
      for (final (contentType, body) in [
        (null, problemBody('not_found')),
        ('application/json', problemBody('not_found')),
        ('text/html', '<h1>502 Bad Gateway</h1>'),
        (problemJson, ''),
        (problemJson, 'not json'),
        (problemJson, '[]'),
        (problemJson, '{"status": 404}'),
        (problemJson, '{"code": 404}'),
      ]) {
        expect(
          ApiProblem.tryParse(contentType: contentType, body: body),
          isNull,
          reason: '$contentType $body',
        );
      }
    });

    test('ignores the whole problem when a field error is malformed', () {
      for (final errors in [
        '"not a list"',
        '[{"pointer": "/title"}]',
        '[{"pointer": "/title", "code": "too_long"}, {"code": "x"}]',
        '[{"pointer": 1, "code": "x"}]',
        '[null]',
      ]) {
        expect(
          ApiProblem.tryParse(
            contentType: problemJson,
            body: problemBody('validation_failed', errors: errors),
          ),
          isNull,
          reason: errors,
        );
      }
    });
  });

  group('ApiErrorResponse.fromResponse', () {
    ApiErrorResponse fromStatus(int status, {String code = 'some_code'}) =>
        ApiErrorResponse.fromResponse(
          statusCode: status,
          contentType: problemJson,
          body: problemBody(code),
        );

    test('picks the exception type from the status', () {
      expect(fromStatus(400), isA<ApiBadRequestException>());
      expect(fromStatus(401), isA<ApiUnauthorizedException>());
      expect(fromStatus(403), isA<ApiForbiddenException>());
      expect(fromStatus(404), isA<ApiNotFoundException>());
      expect(fromStatus(409), isA<ApiConflictException>());
      expect(fromStatus(422), isA<ApiValidationException>());
      expect(fromStatus(429), isA<ApiRateLimitedException>());
      expect(fromStatus(503), isA<ApiUnavailableException>());
      for (final status in [300, 405, 418, 500, 502]) {
        expect(
          fromStatus(status),
          isA<ApiStatusException>().having(
            (e) => e.statusCode,
            'statusCode',
            status,
          ),
        );
      }
    });

    test('keeps the status and code', () {
      for (final status in [400, 401, 403, 404, 409, 422, 429, 503, 500]) {
        final error = fromStatus(status, code: 'code_$status');
        expect(error.statusCode, status);
        expect(error.code, 'code_$status');
      }
    });

    test('carries field errors of a validation problem', () {
      final error = ApiErrorResponse.fromResponse(
        statusCode: 422,
        contentType: problemJson,
        body: problemBody(
          'validation_failed',
          errors: '[{"pointer": "/title", "code": "too_long"}]',
        ),
      );
      expect(
        error,
        isA<ApiValidationException>().having(
          (e) => e.fieldErrors,
          'fieldErrors',
          const [ApiFieldError(pointer: '/title', code: 'too_long')],
        ),
      );
    });

    test('falls back to the status alone without a problem body', () {
      final error = ApiErrorResponse.fromResponse(
        statusCode: 422,
        contentType: 'text/html',
        body: '<h1>error</h1>',
      );
      expect(error, isA<ApiValidationException>());
      expect(error.code, isNull);
      expect((error as ApiValidationException).fieldErrors, isEmpty);
    });

    test('describes itself with status and code only', () {
      expect(
        fromStatus(404, code: 'not_found').toString(),
        'ApiNotFoundException: 404 not_found',
      );
      expect(
        ApiErrorResponse.fromResponse(
          statusCode: 500,
          contentType: 'text/plain',
          body: 'secret detail',
        ).toString(),
        'ApiStatusException: 500',
      );
    });
  });
}
