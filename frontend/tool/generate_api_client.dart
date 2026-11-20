/// Regenerates the API client (`lib/data/api/generated/`) from the backend's
/// OpenAPI document (`../backend/openapi.json`), then applies `dart fix` and
/// `dart format` so the generated code passes the same analysis as
/// hand-written code.
///
/// ```sh
/// dart run tool/generate_api_client.dart
/// ```
///
/// Run it after `backend/openapi.json` changes and commit the result. CI runs it
/// and fails if anything changes. Never edit the generated files by hand.
library;

import 'dart:io';

const String _output = 'lib/data/api/generated';

Future<void> main() async {
  for (final (executable, args) in [
    ('dart', ['run', 'swagger_parser']),
    ('dart', ['fix', '--apply', _output]),
    ('dart', ['format', _output]),
  ]) {
    final process = await Process.start(
      executable,
      args,
      mode: ProcessStartMode.inheritStdio,
    );
    final code = await process.exitCode;
    if (code != 0) {
      stderr.writeln('$executable ${args.join(' ')} failed with $code');
      exitCode = code;
      return;
    }
  }
  // swagger_parser's lock while it writes; not part of the output.
  final lock = File('$_output/.swagger_parser.lock');
  if (lock.existsSync()) lock.deleteSync();
}
