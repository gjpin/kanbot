import 'package:kanbot/data/api/generated/kanbot_api.dart' as api;
import 'package:kanbot/data/repositories/api_result.dart';
import 'package:kanbot/data/repositories/mappers.dart';
import 'package:kanbot/data/services/api_connection.dart';
import 'package:kanbot/domain/models/list_page.dart';
import 'package:kanbot/domain/models/team.dart';
import 'package:kanbot/utils/result.dart';

/// Teams and their members. Nothing is cached (see
/// `OrganizationsRepository`).
class TeamsRepository {
  TeamsRepository({required this._connection});

  final ApiConnection _connection;

  api.TeamsClient get _client => _connection.api.teams;

  /// A page of the teams the user may see, after [after] (a previous
  /// page's `next`).
  Future<Result<ListPage<TeamSummary>>> list({String? after}) =>
      apiResult(() async {
        final page = await _client.listTeams(after: after);
        return ListPage(
          items: page.teams.map(teamSummaryFrom).toList(),
          next: page.next,
        );
      });

  Future<Result<Team>> get(String id) =>
      apiResult(() async => teamFrom(await _client.getTeam(id: id)));

  /// Creates a team, with the user as its maintainer.
  Future<Result<Team>> create({required String slug, required String name}) =>
      apiResult(
        () async => teamFrom(
          await _client.createTeam(
            body: api.NewTeamDto(slug: slug, name: name),
          ),
        ),
      );

  /// Changes the fields that are not `null`. Clearing the identity
  /// provider group is [clearIdpGroup].
  Future<Result<Team>> update(
    String id, {
    String? slug,
    String? name,
    String? idpGroup,
  }) => apiResult(
    () async => teamFrom(
      await _client.updateTeam(
        id: id,
        body: api.TeamChangesDto(slug: slug, name: name, idpGroup: idpGroup),
      ),
    ),
  );

  Future<Result<Team>> clearIdpGroup(String id) =>
      apiResult(() async => teamFrom(await _client.clearTeamIdpGroup(id: id)));

  Future<Result<void>> delete(String id) =>
      apiResult(() => _client.deleteTeam(id: id));

  /// A page of the team's members, after [after] (a previous page's
  /// `next`).
  Future<Result<MemberPage>> members(String id, {String? after}) =>
      apiResult(() async {
        final page = await _client.listTeamMembers(id: id, after: after);
        return MemberPage(
          members: page.members.map(memberFrom).toList(),
          next: page.next,
        );
      });

  /// Adds [userId] with [role], or changes their role.
  Future<Result<void>> setMember(String id, String userId, TeamRole role) =>
      apiResult(
        () => _client.setTeamMember(
          id: id,
          userId: userId,
          body: api.MemberChangeDto(role: teamRoleTo(role)),
        ),
      );

  Future<Result<void>> removeMember(String id, String userId) =>
      apiResult(() => _client.removeTeamMember(id: id, userId: userId));
}
