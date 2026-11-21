/// What a page shows for data it loads: loading, the data, or why it
/// failed (AGENTS.md §4: an explicit error state).
sealed class Loadable<T> {
  const Loadable();
}

final class Loading<T> extends Loadable<T> {
  const Loading();
}

final class Loaded<T> extends Loadable<T> {
  const Loaded(this.value);

  final T value;
}

final class LoadFailed<T> extends Loadable<T> {
  const LoadFailed(this.error);

  final Exception error;
}
