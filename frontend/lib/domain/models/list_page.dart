/// A page of a list the server returns a page at a time (teams,
/// organizations); [next] fetches the following one.
final class ListPage<T> {
  const ListPage({required this.items, this.next});

  final List<T> items;

  /// Opaque: where the next page starts, or `null` on the last one.
  final String? next;
}
