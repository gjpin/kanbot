import 'package:kanbot/data/repositories/organizations_repository.dart';
import 'package:kanbot/data/repositories/teams_repository.dart';
import 'package:kanbot/domain/models/list_page.dart';
import 'package:kanbot/domain/models/organization.dart';
import 'package:kanbot/domain/models/team.dart';
import 'package:kanbot/domain/models/user.dart';
import 'package:kanbot/ui/core/loadable.dart';
import 'package:kanbot/ui/core/view_model.dart';
import 'package:kanbot/utils/result.dart';

/// An organization with the admins and the teams that have access loaded
/// so far. A list's `next`, when set, means there are more
/// ([OrganizationViewModel.loadMoreAdmins],
/// [OrganizationViewModel.loadMoreLinks]).
typedef OrganizationDetails = ({
  Organization organization,
  ListPage<UserSummary> admins,
  ListPage<TeamLink> links,
});

/// The lists of an organization that come a page at a time.
enum _List { admins, links }

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

  /// Bumped by [load]: an answer that arrives after a newer load started
  /// is dropped, so the page never goes back to older data.
  int _generation = 0;

  Future<void> load() async {
    final generation = ++_generation;
    if (_details is! Loaded) {
      _details = const Loading();
      notifyListeners();
    }
    // In parallel; a contract break is rethrown as itself (not wrapped).
    final organizationLoad = _organizations.get(id);
    final adminsLoad = _organizations.admins(id);
    final linksLoad = _organizations.teamLinks(id);
    await Future.wait([organizationLoad, adminsLoad, linksLoad]);
    if (generation != _generation) return;
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

  final Set<_List> _loadingMore = {};

  /// Whether the next page of admins is loading.
  bool get loadingMoreAdmins => _loadingMore.contains(_List.admins);

  /// Whether the next page of linked teams is loading.
  bool get loadingMoreLinks => _loadingMore.contains(_List.links);

  /// Appends the next page of admins, if there is one.
  Future<Result<void>> loadMoreAdmins() => _loadMore(
    _List.admins,
    (details) => details.admins,
    (after) => _organizations.admins(id, after: after),
    (details, admins) => (
      organization: details.organization,
      admins: admins,
      links: details.links,
    ),
  );

  /// Appends the next page of linked teams, if there is one.
  Future<Result<void>> loadMoreLinks() => _loadMore(
    _List.links,
    (details) => details.links,
    (after) => _organizations.teamLinks(id, after: after),
    (details, links) => (
      organization: details.organization,
      admins: details.admins,
      links: links,
    ),
  );

  /// Appends the next page of [list] (read with [pageOf], fetched with
  /// [fetch], put back with [replace]). A page that arrives after a reload
  /// is dropped: the reload has newer data. The page is appended to the
  /// details as they are when it arrives, so the other list's pages loaded
  /// meanwhile stay.
  Future<Result<void>> _loadMore<T>(
    _List list,
    ListPage<T> Function(OrganizationDetails details) pageOf,
    Future<Result<ListPage<T>>> Function(String after) fetch,
    OrganizationDetails Function(OrganizationDetails details, ListPage<T> page)
    replace,
  ) async {
    final current = _details;
    if (_loadingMore.contains(list) ||
        current is! Loaded<OrganizationDetails>) {
      return const Ok(null);
    }
    final after = pageOf(current.value).next;
    if (after == null) return const Ok(null);
    final generation = _generation;
    _loadingMore.add(list);
    notifyListeners();
    final result = await fetch(after);
    _loadingMore.remove(list);
    final latest = _details;
    if (generation != _generation || latest is! Loaded<OrganizationDetails>) {
      notifyListeners();
      return const Ok(null);
    }
    switch (result) {
      case Ok(:final value):
        final loaded = pageOf(latest.value);
        _details = Loaded(
          replace(
            latest.value,
            ListPage(
              items: [...loaded.items, ...value.items],
              next: value.next,
            ),
          ),
        );
        notifyListeners();
        return const Ok(null);
      case Failure(:final error):
        notifyListeners();
        return Failure(error);
    }
  }

  /// Bumped on every reload, so controls showing a choice (a role, an
  /// access) are rebuilt from what the server has.
  int get revision => _revision;
  int _revision = 0;

  /// Whether a change (and the reload after it) is running: the page
  /// disables the controls that start one meanwhile, so a double tap sends
  /// one request.
  bool get busy => _changes > 0;
  int _changes = 0;

  /// Runs [change], then reloads, on failure too: a control may show a
  /// choice the server refused.
  Future<Result<T>> _change<T>(Future<Result<T>> change) async {
    _changes++;
    notifyListeners();
    try {
      final result = await change;
      _revision++;
      await load();
      return result;
    } finally {
      _changes--;
      notifyListeners();
    }
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
