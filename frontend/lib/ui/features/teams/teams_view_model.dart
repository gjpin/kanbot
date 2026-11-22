import 'package:kanbot/data/repositories/teams_repository.dart';
import 'package:kanbot/domain/models/list_page.dart';
import 'package:kanbot/domain/models/team.dart';
import 'package:kanbot/ui/core/loadable.dart';
import 'package:kanbot/ui/core/paged_view_model.dart';
import 'package:kanbot/utils/result.dart';

/// The teams the user may see, a page at a time.
class TeamsViewModel extends PagedViewModel<TeamSummary> {
  TeamsViewModel({required this._repository});

  final TeamsRepository _repository;

  Loadable<List<TeamSummary>> get teams => items;

  @override
  Future<Result<ListPage<TeamSummary>>> fetch({String? after}) =>
      _repository.list(after: after);

  Future<Result<Team>> create(String slug, String name) =>
      _repository.create(slug: slug, name: name);
}
