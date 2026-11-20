/// Builds the release web app with its Content Security Policy.
///
/// ```sh
/// dart run tool/build_web.dart --api-base-url=https://api.example.com
/// ```
///
/// Release web builds must go through this script (AGENTS.md §2): a plain
/// `flutter build web` loads CanvasKit from a CDN and ships without a CSP.
/// Extra arguments (for example `--wasm`) are passed to `flutter build web`.
library;

import 'dart:io';

import 'package:kanbot/config/api_config.dart';

import 'web_csp.dart';

const String _apiBaseUrlFlag = '--api-base-url=';

Future<void> main(List<String> args) async {
  final raw = args
      .where((arg) => arg.startsWith(_apiBaseUrlFlag))
      .map((arg) => arg.substring(_apiBaseUrlFlag.length))
      .firstOrNull;
  if (raw == null) {
    stderr.writeln('usage: dart run tool/build_web.dart $_apiBaseUrlFlag<url>');
    exitCode = 64;
    return;
  }
  final apiBaseUrl = parseApiBaseUrl(raw, release: true);

  final build = await Process.start('flutter', [
    'build',
    'web',
    '--release',
    '--no-web-resources-cdn',
    '--dart-define=API_BASE_URL=$apiBaseUrl',
    ...args.where((arg) => !arg.startsWith(_apiBaseUrlFlag)),
  ], mode: ProcessStartMode.inheritStdio);
  final buildExitCode = await build.exitCode;
  if (buildExitCode != 0) {
    exitCode = buildExitCode;
    return;
  }

  final index = File('build/web/index.html');
  await index.writeAsString(
    injectContentSecurityPolicy(
      await index.readAsString(),
      contentSecurityPolicy(apiBaseUrl),
    ),
  );
  stdout.writeln('Content Security Policy added to ${index.path}');
}
