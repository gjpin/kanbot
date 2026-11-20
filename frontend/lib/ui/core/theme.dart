import 'package:flutter/widgets.dart';
import 'package:shad/shad.dart';

/// The app's shad themes: one style and one color scheme, in light and dark.
///
/// These are created once. A theme rebuilt on every `build()` compares unequal
/// to itself and restarts the theme animation.
abstract final class AppTheme {
  static final ShadThemeData light = ShadThemeData(
    brightness: Brightness.light,
    colorScheme: const ShadZincColorScheme.light(),
    style: ShadStyleTokens.nova,
  );

  static final ShadThemeData dark = ShadThemeData(
    brightness: Brightness.dark,
    colorScheme: const ShadZincColorScheme.dark(),
    style: ShadStyleTokens.nova,
  );
}
