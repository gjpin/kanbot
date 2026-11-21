import 'package:kanbot/domain/models/user.dart';

/// One change to an organization or a team.
final class AuditEntry {
  const AuditEntry({
    required this.id,
    required this.at,
    required this.actor,
    required this.action,
    required this.targetType,
    required this.targetId,
    required this.policyIds,
  });

  final int id;
  final DateTime at;
  final UserSummary actor;

  /// What happened, for example `organization.team_linked`.
  final String action;

  /// `organization` or `team`.
  final String targetType;
  final String targetId;

  /// The policies that allowed it.
  final List<String> policyIds;
}

/// A page of the audit log, newest first.
final class AuditPage {
  const AuditPage({required this.entries, required this.nextBefore});

  final List<AuditEntry> entries;

  /// Where the next page starts; `null` on the last page.
  final int? nextBefore;
}
