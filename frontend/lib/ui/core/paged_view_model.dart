import 'package:flutter/foundation.dart';
import 'package:kanbot/domain/models/list_page.dart';
import 'package:kanbot/ui/core/loadable.dart';
import 'package:kanbot/ui/core/view_model.dart';
import 'package:kanbot/utils/result.dart';

/// A list the server returns a page at a time: [load] gets the first page,
/// [loadMore] appends the next one while [hasMore].
abstract class PagedViewModel<T> extends ViewModel {
  Loadable<List<T>> _items = const Loading();
  String? _next;
  bool _loadingMore = false;
  Exception? _moreError;

  /// Bumped by [load]: a page that arrives after a reload is dropped.
  int _generation = 0;

  /// The pages loaded so far.
  Loadable<List<T>> get items => _items;

  /// Whether the server has another page.
  bool get hasMore => _next != null;
  bool get loadingMore => _loadingMore;

  /// Why loading the next page failed; the pages loaded stay.
  Exception? get moreError => _moreError;

  /// The page after [after] (a previous page's `next`), or the first.
  @protected
  Future<Result<ListPage<T>>> fetch({String? after});

  Future<void> load() async {
    final generation = ++_generation;
    _items = const Loading();
    _next = null;
    _loadingMore = false;
    _moreError = null;
    notifyListeners();
    final result = await fetch();
    if (generation != _generation) return;
    switch (result) {
      case Ok(:final value):
        _items = Loaded(value.items);
        _next = value.next;
      case Failure(:final error):
        _items = LoadFailed(error);
    }
    notifyListeners();
  }

  Future<void> loadMore() async {
    final after = _next;
    final current = _items;
    if (_loadingMore || after == null || current is! Loaded<List<T>>) return;
    final generation = _generation;
    _loadingMore = true;
    _moreError = null;
    notifyListeners();
    final result = await fetch(after: after);
    if (generation != _generation) return;
    switch (result) {
      case Ok(:final value):
        _items = Loaded([...current.value, ...value.items]);
        _next = value.next;
      case Failure(:final error):
        _moreError = error;
    }
    _loadingMore = false;
    notifyListeners();
  }
}
