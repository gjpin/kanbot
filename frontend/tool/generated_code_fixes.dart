/// Fixes applied to swagger_parser's output by `generate_api_client.dart`,
/// before `dart fix` and `dart format`, so the generated client passes the
/// same analysis as hand-written code.
library;

// swagger_parser writes double quotes; `dart fix` makes them single later.
final RegExp _securityBlock = RegExp(
  r'''(['"]openapi\.security['"]\s*:\s*\[)(.*?)(\]\s*,\s*['"]openapi\.securitySchemes['"])''',
  dotAll: true,
);

final RegExp _emptyScopes = RegExp(r'''(['"][^'"]*['"]\s*:\s*)\[\]''');

/// Types the empty scope lists of security requirements.
///
/// swagger_parser writes `'openapi.security': [{'bearer': []}]`, whose `[]`
/// has no type the analyzer can infer (`inference_failure_on_collection_literal`
/// under `strict-inference`). Scopes are strings (OpenAPI security
/// requirement object), so it becomes `<String>[]`. Nothing outside the
/// `'openapi.security'` entry changes.
String typeSecurityScopes(String source) => source.replaceAllMapped(
  _securityBlock,
  (block) =>
      '${block[1]}'
      '${block[2]!.replaceAllMapped(_emptyScopes, (scope) => '${scope[1]}<String>[]')}'
      '${block[3]}',
);
