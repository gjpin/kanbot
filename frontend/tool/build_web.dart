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

/// Whether [args] set `API_BASE_URL`, in any of `flutter build`'s forms:
/// `--dart-define=API_BASE_URL=...`, `--dart-define API_BASE_URL=...`, or
/// a `--dart-define-from-file`, which this script cannot see into.
bool definesApiBaseUrl(List<String> args) {
  for (var i = 0; i < args.length; i++) {
    final arg = args[i];
    final next = i + 1 < args.length ? args[i + 1] : '';
    if (arg.startsWith('--dart-define=API_BASE_URL') ||
        (arg == '--dart-define' && next.startsWith('API_BASE_URL')) ||
        arg.startsWith('--dart-define-from-file')) {
      return true;
    }
  }
  return false;
}

Future<void> main(List<String> args) async {
  if (definesApiBaseUrl(args)) {
    stderr.writeln(
      'The web app talks to the server it is loaded from: '
      'do not set API_BASE_URL (nor use --dart-define-from-file).',
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
