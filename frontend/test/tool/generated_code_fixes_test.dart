import 'package:flutter_test/flutter_test.dart';

import '../../tool/generated_code_fixes.dart';

void main() {
  group('typeSecurityScopes', () {
    test('types empty scope lists of security requirements', () {
      const generated = '''
    Map<String, Object?> extra = const {
      'openapi.security': [
        {'bearer': []},
        {'session': [], 'bearer': []},
      ],
      'openapi.securitySchemes': {
        'bearer': {'type': 'http', 'scheme': 'bearer'},
      },
    },''';

      expect(typeSecurityScopes(generated), '''
    Map<String, Object?> extra = const {
      'openapi.security': [
        {'bearer': <String>[]},
        {'session': <String>[], 'bearer': <String>[]},
      ],
      'openapi.securitySchemes': {
        'bearer': {'type': 'http', 'scheme': 'bearer'},
      },
    },''');
    });

    test('handles the double quotes swagger_parser writes', () {
      const generated = '''
      "openapi.security": [
        {"bearer": []},
      ],
      "openapi.securitySchemes": {''';
      expect(typeSecurityScopes(generated), '''
      "openapi.security": [
        {"bearer": <String>[]},
      ],
      "openapi.securitySchemes": {''');
    });

    test('keeps scopes that are already listed', () {
      const generated =
          "{'openapi.security': [{'oauth': ['read']}], "
          "'openapi.securitySchemes': {}}";
      expect(typeSecurityScopes(generated), generated);
    });

    test('leaves everything outside security requirements alone', () {
      const generated =
          "final defaults = {'tags': []};\n"
          "const extra = {'openapi.security': [{'bearer': []}], "
          "'openapi.securitySchemes': {}};\n"
          "final more = {'items': []};";
      expect(
        typeSecurityScopes(generated),
        "final defaults = {'tags': []};\n"
        "const extra = {'openapi.security': [{'bearer': <String>[]}], "
        "'openapi.securitySchemes': {}};\n"
        "final more = {'items': []};",
      );
    });

    test('changes nothing in code without security requirements', () {
      const generated = "class A { final x = {'a': []}; }";
      expect(typeSecurityScopes(generated), generated);
    });
  });
}
