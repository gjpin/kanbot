import 'package:kanbot/data/repositories/teams_repository.dart';
import 'package:kanbot/domain/models/team.dart';
import 'package:kanbot/domain/models/user.dart';
import 'package:kanbot/ui/core/loadable.dart';
import 'package:kanbot/ui/core/view_model.dart';
import 'package:kanbot/utils/result.dart';

/// A team and the members loaded so far; `next`, when set, means there
/// are more ([TeamViewModel.loadMore]).
typedef TeamDetails = ({Team team, List<Member> members, String? next});

/// One team: its settings, identity provider group and members.
class TeamViewModel extends ViewModel {
  TeamViewModel({required this.id, required this._teams});

  final String id;
  final TeamsRepository _teams;

  Loadable<TeamDetails> _details = const Loading();

  Loadable<TeamDetails> get details => _details;

  Future<void> load() async {
    if (_details is! Loaded) {
      _details = const Loading();
      notifyListeners();
    }
    final (team, members) = await (_teams.get(id), _teams.members(id)).wait;
    _details = switch ((team, members)) {
      (Ok(value: final t), Ok(value: final m)) => Loaded((
        team: t,
        members: m.members,
        next: m.next,
      )),
      (Failure(:final error), _) ||
      (_, Failure(:final error)) => LoadFailed(error),
    };
    notifyListeners();
  }

  bool _loadingMore = false;

  /// Appends the next page of members, if there is one.
  Future<Result<void>> loadMore() async {
    final current = _details;
    if (_loadingMore || current is! Loaded<TeamDetails>) {
      return const Ok(null);
    }
    final after = current.value.next;
    if (after == null) return const Ok(null);
    _loadingMore = true;
    final page = await _teams.members(id, after: after);
    _loadingMore = false;
    switch (page) {
      case Ok(:final value):
        _details = Loaded((
          team: current.value.team,
          members: [...current.value.members, ...value.members],
          next: value.next,
        ));
        notifyListeners();
        return const Ok(null);
      case Failure(:final error):
        return Failure(error);
    }
  }

  /// Bumped on every reload, so controls showing a choice (a role, an
  /// access) are rebuilt from what the server has.
  int get revision => _revision;
  int _revision = 0;

  /// Runs [change], then reloads, on failure too: a control may show a
  /// choice the server refused.
  Future<Result<T>> _change<T>(Future<Result<T>> change) async {
    final result = await change;
    _revision++;
    await load();
    return result;
  }

  Future<Result<Team>> rename(String slug, String name) =>
      _change(_teams.update(id, slug: slug, name: name));

  Future<Result<void>> delete() => _teams.delete(id);

  /// Syncs the members with [group]; empty stops syncing.
  Future<Result<Team>> setIdpGroup(String group) => _change(
    group.isEmpty
        ? _teams.clearIdpGroup(id)
        : _teams.update(id, idpGroup: group),
  );

  Future<Result<void>> setMember(UserSummary user, TeamRole role) =>
      _change(_teams.setMember(id, user.id, role));

  Future<Result<void>> removeMember(UserSummary user) =>
      _change(_teams.removeMember(id, user.id));
}
