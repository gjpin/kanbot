import 'package:flutter/foundation.dart';
import 'package:kanbot/data/repositories/teams_repository.dart';
import 'package:kanbot/domain/models/team.dart';
import 'package:kanbot/ui/core/loadable.dart';
import 'package:kanbot/utils/result.dart';

/// The teams the user may see.
class TeamsViewModel extends ChangeNotifier {
  TeamsViewModel({required this._repository});

  final TeamsRepository _repository;

  Loadable<List<TeamSummary>> _teams = const Loading();

  Loadable<List<TeamSummary>> get teams => _teams;

  Future<void> load() async {
    _teams = const Loading();
    notifyListeners();
    _teams = switch (await _repository.list()) {
      Ok(:final value) => Loaded(value),
      Failure(:final error) => LoadFailed(error),
    };
    notifyListeners();
  }

  Future<Result<Team>> create(String slug, String name) =>
      _repository.create(slug: slug, name: name);
}
