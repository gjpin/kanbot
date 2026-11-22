import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';

/// Runs before every test file: golden images compare with a little
/// tolerance, since anti-aliasing differs slightly between the machines
/// that write them and CI. Text uses the test font (blocks), the same on
/// every platform, so layout changes still show.
Future<void> testExecutable(FutureOr<void> Function() testMain) async {
  final comparator = goldenFileComparator;
  if (comparator is LocalFileComparator) {
    goldenFileComparator = TolerantComparator(comparator.basedir);
  }
  await testMain();
}

/// A [LocalFileComparator] that accepts up to [tolerance] of the pixels
/// differing.
class TolerantComparator extends LocalFileComparator {
  TolerantComparator(Uri basedir, {this.tolerance = 0.005})
    : super(basedir.resolve('golden_test.dart'));

  /// The share of pixels that may differ, from 0 to 1.
  final double tolerance;

  @override
  Future<bool> compare(Uint8List imageBytes, Uri golden) async {
    final result = await GoldenFileComparator.compareLists(
      imageBytes,
      await getGoldenBytes(golden),
    );
    if (result.passed || result.diffPercent <= tolerance) {
      result.dispose();
      return true;
    }
    final error = await generateFailureOutput(result, golden, basedir);
    result.dispose();
    throw FlutterError(error);
  }
}
