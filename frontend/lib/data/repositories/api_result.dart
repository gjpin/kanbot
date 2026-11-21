import 'package:kanbot/data/services/api_exception.dart';
import 'package:kanbot/utils/result.dart';

/// Runs an API [call], turning an [ApiException] into a [Failure]. Other
/// errors (a response that does not match the contract, AGENTS.md §5)
/// propagate: they are bugs, not outcomes.
Future<Result<T>> apiResult<T>(Future<T> Function() call) async {
  try {
    return Ok(await call());
  } on ApiException catch (error) {
    return Failure(error);
  }
}
