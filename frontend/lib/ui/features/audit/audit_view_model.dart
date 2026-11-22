import 'package:kanbot/data/repositories/users_repository.dart';
import 'package:kanbot/domain/models/audit.dart';
import 'package:kanbot/ui/core/loadable.dart';
import 'package:kanbot/ui/core/view_model.dart';
import 'package:kanbot/utils/result.dart';

/// The audit log, newest first, a page at a time.
class AuditViewModel extends ViewModel {
  AuditViewModel({required this._users});

  final UsersRepository _users;

  Loadable<List<AuditEntry>> _entries = const Loading();
  int? _nextBefore;
  bool _loadingMore = false;
  Exception? _moreError;

  /// Bumped by [load]: a page that arrives after a reload is dropped.
  int _generation = 0;

  Loadable<List<AuditEntry>> get entries => _entries;

  /// Whether older entries exist.
  bool get hasMore => _nextBefore != null;
  bool get loadingMore => _loadingMore;

  /// Why loading older entries failed.
  Exception? get moreError => _moreError;

  Future<void> load() async {
    final generation = ++_generation;
    _entries = const Loading();
    _nextBefore = null;
    _loadingMore = false;
    _moreError = null;
    notifyListeners();
    final result = await _users.audit();
    if (generation != _generation) return;
    switch (result) {
      case Ok(:final value):
        _entries = Loaded(value.entries);
        _nextBefore = value.nextBefore;
      case Failure(:final error):
        _entries = LoadFailed(error);
    }
    notifyListeners();
  }

  Future<void> loadMore() async {
    final before = _nextBefore;
    final current = _entries;
    if (_loadingMore ||
        before == null ||
        current is! Loaded<List<AuditEntry>>) {
      return;
    }
    final generation = _generation;
    _loadingMore = true;
    _moreError = null;
    notifyListeners();
    final result = await _users.audit(before: before);
    if (generation != _generation) return;
    switch (result) {
      case Ok(:final value):
        _entries = Loaded([...current.value, ...value.entries]);
        _nextBefore = value.nextBefore;
      case Failure(:final error):
        _moreError = error;
    }
    _loadingMore = false;
    notifyListeners();
  }
}
