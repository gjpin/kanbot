import 'package:kanbot/data/repositories/api_result.dart';
import 'package:kanbot/data/repositories/mappers.dart';
import 'package:kanbot/data/services/api_connection.dart';
import 'package:kanbot/domain/models/audit.dart';
import 'package:kanbot/domain/models/user.dart';
import 'package:kanbot/utils/result.dart';

/// Other users, and the audit log.
class UsersRepository {
  UsersRepository({required this._connection});

  final ApiConnection _connection;

  /// Users whose name contains [query] (at most 20).
  Future<Result<List<UserSummary>>> search(String query) => apiResult(
    () async =>
        (await _connection.api.users.searchUsers(query2: query))
            .map(userSummaryFrom)
            .toList(),
  );

  /// A page of the audit log, newest first, older than [before].
  Future<Result<AuditPage>> audit({int? before}) => apiResult(
    () async => auditPageFrom(
      await _connection.api.audit.listAuditEntries(before: before),
    ),
  );
}
