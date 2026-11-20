/// Regenerates the API client (`lib/data/api/generated/`) from the backend's
/// OpenAPI document (`../backend/openapi.json`), then applies the fixes in
/// `generated_code_fixes.dart`, `dart fix` and `dart format` so the
/// generated code passes the same analysis as hand-written code.
///
/// ```sh
/// dart run tool/generate_api_client.dart
/// ```
///
/// Run it after `backend/openapi.json` changes and commit the result. CI runs it
/// and fails if anything changes. Never edit the generated files by hand.
library;

import 'dart:io';

import 'generated_code_fixes.dart';

const String _output = 'lib/data/api/generated';

Future<void> main() async {
  if (!await _run('dart', ['run', 'swagger_parser'])) return;
  for (final file in Directory(_output).listSync(recursive: true)) {
    if (file is File && file.path.endsWith('.dart')) {
      final source = file.readAsStringSync();
      final fixed = typeSecurityScopes(source);
      if (fixed != source) file.writeAsStringSync(fixed);
    }
  }
  for (final (executable, args) in [
    ('dart', ['fix', '--apply', _output]),
    ('dart', ['format', _output]),
  ]) {
    if (!await _run(executable, args)) return;
  }
  // swagger_parser's lock while it writes; not part of the output.
  final lock = File('$_output/.swagger_parser.lock');
  if (lock.existsSync()) lock.deleteSync();
}

/// Runs a command with this process's output; on failure, sets the exit
/// code and returns false.
Future<bool> _run(String executable, List<String> args) async {
  final process = await Process.start(
    executable,
    args,
    mode: ProcessStartMode.inheritStdio,
  );
  final code = await process.exitCode;
  if (code != 0) {
    stderr.writeln('$executable ${args.join(' ')} failed with $code');
    exitCode = code;
    return false;
  }
  return true;
}
