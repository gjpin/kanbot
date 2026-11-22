import 'package:kanbot/data/api/generated/kanbot_api.dart' as api;
import 'package:kanbot/data/repositories/api_result.dart';
import 'package:kanbot/data/repositories/mappers.dart';
import 'package:kanbot/data/services/api_connection.dart';
import 'package:kanbot/domain/models/list_page.dart';
import 'package:kanbot/domain/models/organization.dart';
import 'package:kanbot/domain/models/user.dart';
import 'package:kanbot/utils/result.dart';

/// Organizations, their admins and team links. Nothing is cached: every
/// call asks the server, so what the user sees follows the server's
/// authorization.
class OrganizationsRepository {
  OrganizationsRepository({required this._connection});

  final ApiConnection _connection;

  api.OrganizationsClient get _client => _connection.api.organizations;

  /// A page of the organizations the user may read, after [after] (a
  /// previous page's `next`).
  Future<Result<ListPage<OrganizationSummary>>> list({String? after}) =>
      apiResult(() async {
        final page = await _client.listOrganizations(after: after);
        return ListPage(
          items: page.organizations.map(organizationSummaryFrom).toList(),
          next: page.next,
        );
      });

  Future<Result<Organization>> get(String id) => apiResult(
    () async => organizationFrom(await _client.getOrganization(id: id)),
  );

  Future<Result<Organization>> create({
    required String slug,
    required String name,
  }) => apiResult(
    () async => organizationFrom(
      await _client.createOrganization(
        body: api.NewOrganizationDto(slug: slug, name: name),
      ),
    ),
  );

  /// Changes the fields that are not `null`.
  Future<Result<Organization>> update(
    String id, {
    String? slug,
    String? name,
  }) => apiResult(
    () async => organizationFrom(
      await _client.updateOrganization(
        id: id,
        body: api.OrganizationChangesDto(slug: slug, name: name),
      ),
    ),
  );

  /// Links the organization to the OpenShell workspace named [workspace].
  Future<Result<Organization>> linkOpenShellWorkspace(
    String id,
    String workspace,
  ) => apiResult(
    () async => organizationFrom(
      await _client.linkOrganizationOpenshellWorkspace(
        id: id,
        body: api.OpenShellLinkDto(workspace: workspace),
      ),
    ),
  );

  Future<Result<Organization>> unlinkOpenShellWorkspace(String id) => apiResult(
    () async => organizationFrom(
      await _client.unlinkOrganizationOpenshellWorkspace(id: id),
    ),
  );

  Future<Result<void>> delete(String id) =>
      apiResult(() => _client.deleteOrganization(id: id));

  /// A page of the organization's admins, after [after] (a previous
  /// page's `next`).
  Future<Result<ListPage<UserSummary>>> admins(String id, {String? after}) =>
      apiResult(() async {
        final page = await _client.listOrganizationAdmins(id: id, after: after);
        return ListPage(
          items: page.admins.map(userSummaryFrom).toList(),
          next: page.next,
        );
      });

  Future<Result<void>> addAdmin(String id, String userId) =>
      apiResult(() => _client.addOrganizationAdmin(id: id, userId: userId));

  Future<Result<void>> removeAdmin(String id, String userId) =>
      apiResult(() => _client.removeOrganizationAdmin(id: id, userId: userId));

  /// A page of the teams linked to the organization, after [after] (a
  /// previous page's `next`).
  Future<Result<ListPage<TeamLink>>> teamLinks(String id, {String? after}) =>
      apiResult(() async {
        final page = await _client.listOrganizationTeams(id: id, after: after);
        return ListPage(
          items: page.links.map(teamLinkFrom).toList(),
          next: page.next,
        );
      });

  /// Links [teamId] with [access], or changes its access.
  Future<Result<void>> linkTeam(String id, String teamId, Access access) =>
      apiResult(
        () => _client.linkOrganizationTeam(
          id: id,
          teamId: teamId,
          body: api.TeamLinkChangeDto(access: accessTo(access)),
        ),
      );

  Future<Result<void>> unlinkTeam(String id, String teamId) =>
      apiResult(() => _client.unlinkOrganizationTeam(id: id, teamId: teamId));
}
