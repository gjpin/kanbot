import 'package:flutter/widgets.dart';
import 'package:go_router/go_router.dart';
import 'package:kanbot/config/dependencies.dart';
import 'package:kanbot/domain/models/team.dart';
import 'package:kanbot/routing/router.dart';
import 'package:kanbot/ui/core/app_page.dart';
import 'package:kanbot/ui/core/loadable.dart';
import 'package:kanbot/ui/core/messages.dart';
import 'package:kanbot/ui/core/name_dialog.dart';
import 'package:kanbot/ui/core/section.dart';
import 'package:kanbot/ui/core/user_picker.dart';
import 'package:kanbot/ui/features/teams/team_view_model.dart';
import 'package:kanbot/utils/result.dart';
import 'package:shad/shad.dart';

/// One team: its members and maintainers, and its identity provider group.
/// Members from the identity provider are read-only. Controls the user may
/// not use are hidden; the server checks every change anyway.
class TeamPage extends StatefulWidget {
  const TeamPage({super.key, required this.dependencies, required this.id});

  final AppDependencies dependencies;
  final String id;

  @override
  State<TeamPage> createState() => _TeamPageState();
}

class _TeamPageState extends State<TeamPage> {
  late final TeamViewModel _viewModel = TeamViewModel(
    id: widget.id,
    teams: widget.dependencies.teams,
  );
  final TextEditingController _group = TextEditingController();

  @override
  void initState() {
    super.initState();
    _viewModel.load().ignore();
  }

  @override
  void dispose() {
    _viewModel.dispose();
    _group.dispose();
    super.dispose();
  }

  void _report(Result<Object?> result, {String? success}) {
    if (!mounted) return;
    switch (result) {
      case Failure(:final error):
        showMessage(context, Messages.error(error), error: true);
      case Ok() when success != null:
        showMessage(context, success);
      case Ok():
    }
  }

  Future<void> _rename(Team team) async {
    await showNameDialog<Team>(
      context,
      title: Messages.rename,
      action: Messages.save,
      initialName: team.name,
      initialSlug: team.slug,
      submit: _viewModel.rename,
    );
  }

  Future<void> _delete() async {
    final confirmed = await confirm(
      context,
      title: Messages.deleteTeam,
      description: Messages.deleteTeamConfirm,
      action: Messages.delete,
    );
    if (!confirmed) return;
    final result = await _viewModel.delete();
    if (!mounted) return;
    switch (result) {
      case Ok():
        context.go(Routes.teams);
      case Failure():
        _report(result);
    }
  }

  Future<void> _addMember() async {
    final user = await pickUser(
      context,
      users: widget.dependencies.users,
      title: Messages.addMember,
    );
    if (user != null) {
      _report(await _viewModel.setMember(user, TeamRole.member));
    }
  }

  String _role(TeamRole role) => switch (role) {
    TeamRole.member => Messages.member,
    TeamRole.maintainer => Messages.maintainer,
  };

  @override
  Widget build(BuildContext context) => ListenableBuilder(
    listenable: _viewModel,
    builder: (context, _) {
      final details = _viewModel.details;
      final team = switch (details) {
        Loaded(:final value) => value.team,
        _ => null,
      };
      return AppPage(
        user: widget.dependencies.auth.user,
        title: team?.name ?? Messages.teams,
        actions: [
          if (team != null && team.can(TeamPermission.manage)) ...[
            ShadButton.outline(
              onPressed: () => _rename(team),
              child: const Text(Messages.rename),
            ),
            ShadButton.destructive(
              onPressed: _delete,
              child: const Text(Messages.deleteTeam),
            ),
          ],
        ],
        child: LoadableView(
          loadable: details,
          onRetry: _viewModel.load,
          builder: (context, value) {
            final team = value.team;
            final manage = team.can(TeamPermission.manageMembers);
            return ShadColumn(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              spacing: 6,
              children: [
                if (team.can(TeamPermission.setIdpGroup))
                  _IdpGroupEditor(
                    group: team.idpGroup,
                    controller: _group,
                    onSave: (group) async => _report(
                      await _viewModel.setIdpGroup(group),
                      success: Messages.saved,
                    ),
                  )
                else if (team.idpGroup case final group?)
                  Text('${Messages.idpGroup}: $group'),
                Section(
                  title: Messages.members,
                  action: manage
                      ? ShadButton.outline(
                          size: ShadButtonSize.sm,
                          onPressed: _addMember,
                          child: const Text(Messages.addMember),
                        )
                      : null,
                  children: [
                    for (final member in value.members)
                      ListRow(
                        label: displayName(member.user),
                        trailing: [
                          if (manage &&
                              member.source == MembershipSource.manual) ...[
                            ShadSelect<TeamRole>(
                              initialValue: member.role,
                              options: [
                                for (final role in TeamRole.values)
                                  ShadOption(
                                    value: role,
                                    child: Text(_role(role)),
                                  ),
                              ],
                              selectedOptionBuilder: (context, role) =>
                                  Text(_role(role)),
                              onChanged: (role) async {
                                if (role == null || role == member.role) {
                                  return;
                                }
                                _report(
                                  await _viewModel.setMember(member.user, role),
                                );
                              },
                            ),
                            ShadButton.ghost(
                              size: ShadButtonSize.sm,
                              onPressed: () async => _report(
                                await _viewModel.removeMember(member.user),
                              ),
                              child: const Text(Messages.remove),
                            ),
                          ] else ...[
                            ShadBadge.secondary(
                              child: Text(_role(member.role)),
                            ),
                            if (member.source == MembershipSource.idp)
                              const ShadBadge.outline(
                                child: Text(Messages.fromIdentityProvider),
                              ),
                          ],
                        ],
                      ),
                  ],
                ),
              ],
            );
          },
        ),
      );
    },
  );
}

/// Sets or clears a team's identity provider group (platform admins).
class _IdpGroupEditor extends StatefulWidget {
  const _IdpGroupEditor({
    required this.group,
    required this.controller,
    required this.onSave,
  });

  final String? group;
  final TextEditingController controller;
  final Future<void> Function(String group) onSave;

  @override
  State<_IdpGroupEditor> createState() => _IdpGroupEditorState();
}

class _IdpGroupEditorState extends State<_IdpGroupEditor> {
  @override
  void initState() {
    super.initState();
    widget.controller.text = widget.group ?? '';
  }

  @override
  Widget build(BuildContext context) => ShadCard(
    title: const Text(Messages.idpGroup),
    description: const Text(Messages.idpGroupHint),
    child: ShadPadding.only(
      top: 3,
      child: Wrap(
        spacing: 2,
        runSpacing: 2,
        crossAxisAlignment: WrapCrossAlignment.center,
        children: [
          SizedBox(width: 280, child: ShadInput(controller: widget.controller)),
          ShadButton.outline(
            onPressed: () => widget.onSave(widget.controller.text.trim()),
            child: const Text(Messages.save),
          ),
          if (widget.group != null)
            ShadButton.ghost(
              onPressed: () async {
                widget.controller.clear();
                await widget.onSave('');
              },
              child: const Text(Messages.stopSyncing),
            ),
        ],
      ),
    ),
  );
}
