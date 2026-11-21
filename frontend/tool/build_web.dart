/// Builds the release web app.
///
/// ```sh
/// dart run tool/build_web.dart
/// ```
///
/// Release web builds must go through this script (AGENTS.md §2): a plain
/// `flutter build web` loads CanvasKit from a CDN, which the
/// Content-Security-Policy the backend sends with the app
/// (`backend/src/http/web.rs`, `WEB_DIR`) does not allow. The app talks to
/// the server it is loaded from, so the build needs no API URL. Extra
/// arguments (for example `--wasm`) are passed to `flutter build web`.
library;

import 'dart:io';

Future<void> main(List<String> args) async {
  if (args.any((arg) => arg.startsWith('--dart-define=API_BASE_URL'))) {
    stderr.writeln(
      'The web app talks to the server it is loaded from: '
      'do not set API_BASE_URL.',
    );
    exitCode = 64;
    return;
  }
  final build = await Process.start('flutter', [
    'build',
    'web',
    '--release',
    '--no-web-resources-cdn',
    ...args,
  ], mode: ProcessStartMode.inheritStdio);
  exitCode = await build.exitCode;
}
