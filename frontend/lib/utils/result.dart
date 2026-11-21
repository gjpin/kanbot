/// The outcome of an operation that can fail: a value or an exception.
/// ViewModels switch on it instead of catching (AGENTS.md §4).
sealed class Result<T> {
  const Result();
}

/// A successful outcome.
final class Ok<T> extends Result<T> {
  const Ok(this.value);

  final T value;
}

/// A failed outcome.
final class Failure<T> extends Result<T> {
  const Failure(this.error);

  final Exception error;
}
