import 'package:kanbot/data/repositories/organizations_repository.dart';
import 'package:kanbot/data/repositories/teams_repository.dart';
import 'package:kanbot/domain/models/list_page.dart';
import 'package:kanbot/domain/models/organization.dart';
import 'package:kanbot/domain/models/team.dart';
import 'package:kanbot/domain/models/user.dart';
import 'package:kanbot/ui/core/loadable.dart';
import 'package:kanbot/ui/core/view_model.dart';
import 'package:kanbot/utils/result.dart';

/// An organization with its admins and the teams that have access.
typedef OrganizationDetails = ({
  Organization organization,
  List<UserSummary> admins,
  List<TeamLink> links,
});

/// One organization: its settings, admins and team links.
class OrganizationViewModel extends ViewModel {
  OrganizationViewModel({
    required this.id,
    required this._organizations,
    required this._teams,
  });

  final String id;
  final OrganizationsRepository _organizations;
  final TeamsRepository _teams;

  Loadable<OrganizationDetails> _details = const Loading();

  Loadable<OrganizationDetails> get details => _details;

  Future<void> load() async {
    if (_details is! Loaded) {
      _details = const Loading();
      notifyListeners();
    }
    // In parallel; a contract break is rethrown as itself (not wrapped).
    final organizationLoad = _organizations.get(id);
    final adminsLoad = _organizations.admins(id);
    final linksLoad = _organizations.teamLinks(id);
    await Future.wait([organizationLoad, adminsLoad, linksLoad]);
    final organization = await organizationLoad;
    final admins = await adminsLoad;
    final links = await linksLoad;
    _details = switch ((organization, admins, links)) {
      (Ok(value: final o), Ok(value: final a), Ok(value: final l)) => Loaded((
        organization: o,
        admins: a,
        links: l,
      )),
      (Failure(:final error), _, _) ||
      (_, Failure(:final error), _) ||
      (_, _, Failure(:final error)) => LoadFailed(error),
    };
    notifyListeners();
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

  Future<Result<Organization>> rename(String slug, String name) =>
      _change(_organizations.update(id, slug: slug, name: name));

  Future<Result<void>> delete() => _organizations.delete(id);

  Future<Result<void>> addAdmin(UserSummary user) =>
      _change(_organizations.addAdmin(id, user.id));

  Future<Result<void>> removeAdmin(UserSummary user) =>
      _change(_organizations.removeAdmin(id, user.id));

  Future<Result<void>> linkTeam(String teamId, Access access) =>
      _change(_organizations.linkTeam(id, teamId, access));

  Future<Result<void>> unlinkTeam(String teamId) =>
      _change(_organizations.unlinkTeam(id, teamId));

  Future<Result<Organization>> linkOpenShellWorkspace(String workspace) =>
      _change(_organizations.linkOpenShellWorkspace(id, workspace));

  Future<Result<Organization>> unlinkOpenShellWorkspace() =>
      _change(_organizations.unlinkOpenShellWorkspace(id));

  /// A page of the teams the user can see, to choose one to link.
  Future<Result<ListPage<TeamSummary>>> teams({String? after}) =>
      _teams.list(after: after);
}
