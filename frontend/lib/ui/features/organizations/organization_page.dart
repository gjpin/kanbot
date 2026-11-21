import 'package:flutter/widgets.dart';
import 'package:go_router/go_router.dart';
import 'package:kanbot/config/dependencies.dart';
import 'package:kanbot/domain/models/organization.dart';
import 'package:kanbot/domain/models/team.dart';
import 'package:kanbot/routing/router.dart';
import 'package:kanbot/ui/core/app_page.dart';
import 'package:kanbot/ui/core/loadable.dart';
import 'package:kanbot/ui/core/messages.dart';
import 'package:kanbot/ui/core/name_dialog.dart';
import 'package:kanbot/ui/core/section.dart';
import 'package:kanbot/ui/core/user_picker.dart';
import 'package:kanbot/ui/features/organizations/organization_view_model.dart';
import 'package:kanbot/utils/result.dart';
import 'package:shad/shad.dart';

/// One organization: its admins and the teams with access. Controls the
/// user may not use are hidden; the server checks every change anyway.
class OrganizationPage extends StatefulWidget {
  const OrganizationPage({
    super.key,
    required this.dependencies,
    required this.id,
  });

  final AppDependencies dependencies;
  final String id;

  @override
  State<OrganizationPage> createState() => _OrganizationPageState();
}

class _OrganizationPageState extends State<OrganizationPage> {
  late final OrganizationViewModel _viewModel = OrganizationViewModel(
    id: widget.id,
    organizations: widget.dependencies.organizations,
    teams: widget.dependencies.teams,
  );

  @override
  void initState() {
    super.initState();
    _viewModel.load().ignore();
  }

  @override
  void dispose() {
    _viewModel.dispose();
    super.dispose();
  }

  /// Reports [result]'s failure, if any.
  void _report(Result<Object?> result) {
    if (!mounted) return;
    if (result case Failure(:final error)) {
      showMessage(context, Messages.error(error), error: true);
    }
  }

  Future<void> _rename(Organization organization) async {
    await showNameDialog<Organization>(
      context,
      title: Messages.rename,
      action: Messages.save,
      initialName: organization.name,
      initialSlug: organization.slug,
      submit: _viewModel.rename,
    );
  }

  Future<void> _delete() async {
    final confirmed = await confirm(
      context,
      title: Messages.deleteOrganization,
      description: Messages.deleteOrganizationConfirm,
      action: Messages.delete,
    );
    if (!confirmed) return;
    final result = await _viewModel.delete();
    if (!mounted) return;
    switch (result) {
      case Ok():
        context.go(Routes.home);
      case Failure():
        _report(result);
    }
  }

  Future<void> _addAdmin() async {
    final user = await pickUser(
      context,
      users: widget.dependencies.users,
      title: Messages.addAdmin,
    );
    if (user != null) _report(await _viewModel.addAdmin(user));
  }

  Future<void> _linkTeam() async {
    final link = await showShadDialog<(String, Access)>(
      context: context,
      builder: (context) => LinkTeamDialog(teams: _viewModel.teams),
    );
    if (link != null) _report(await _viewModel.linkTeam(link.$1, link.$2));
  }

  @override
  Widget build(BuildContext context) => ListenableBuilder(
    listenable: _viewModel,
    builder: (context, _) {
      final details = _viewModel.details;
      final organization = switch (details) {
        Loaded(:final value) => value.organization,
        _ => null,
      };
      return AppPage(
        user: widget.dependencies.auth.user,
        title: organization?.name ?? Messages.organizations,
        actions: [
          if (organization != null &&
              organization.can(OrganizationPermission.manage))
            ShadButton.outline(
              onPressed: () => _rename(organization),
              child: const Text(Messages.rename),
            ),
          if (organization != null &&
              organization.can(OrganizationPermission.delete))
            ShadButton.destructive(
              onPressed: _delete,
              child: const Text(Messages.deleteOrganization),
            ),
        ],
        child: LoadableView(
          loadable: details,
          onRetry: _viewModel.load,
          builder: (context, value) => ShadColumn(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            spacing: 6,
            children: [
              Section(
                title: Messages.admins,
                action:
                    value.organization.can(OrganizationPermission.manageAdmins)
                    ? ShadButton.outline(
                        size: ShadButtonSize.sm,
                        onPressed: _addAdmin,
                        child: const Text(Messages.addAdmin),
                      )
                    : null,
                children: [
                  for (final admin in value.admins)
                    ListRow(
                      label: displayName(admin),
                      trailing: [
                        if (value.organization.can(
                          OrganizationPermission.manageAdmins,
                        ))
                          ShadButton.ghost(
                            size: ShadButtonSize.sm,
                            onPressed: () async =>
                                _report(await _viewModel.removeAdmin(admin)),
                            child: const Text(Messages.remove),
                          ),
                      ],
                    ),
                ],
              ),
              Section(
                title: Messages.linkedTeams,
                action:
                    value.organization.can(
                      OrganizationPermission.manageTeamLinks,
                    )
                    ? ShadButton.outline(
                        size: ShadButtonSize.sm,
                        onPressed: _linkTeam,
                        child: const Text(Messages.linkTeam),
                      )
                    : null,
                children: [
                  for (final link in value.links)
                    ListRow(
                      label: link.team.name,
                      onTap: () => context.go(Routes.team(link.team.id)),
                      trailing:
                          value.organization.can(
                            OrganizationPermission.manageTeamLinks,
                          )
                          ? [
                              AccessSelect(
                                value: link.access,
                                onChanged: (access) async => _report(
                                  await _viewModel.linkTeam(
                                    link.team.id,
                                    access,
                                  ),
                                ),
                              ),
                              ShadButton.ghost(
                                size: ShadButtonSize.sm,
                                onPressed: () async => _report(
                                  await _viewModel.unlinkTeam(link.team.id),
                                ),
                                child: const Text(Messages.remove),
                              ),
                            ]
                          : [
                              ShadBadge.secondary(
                                child: Text(_access(link.access)),
                              ),
                            ],
                    ),
                ],
              ),
            ],
          ),
        ),
      );
    },
  );
}

String _access(Access access) => switch (access) {
  Access.read => Messages.read,
  Access.write => Messages.write,
};

/// Chooses `read` or `write`.
class AccessSelect extends StatelessWidget {
  const AccessSelect({super.key, required this.value, required this.onChanged});

  final Access value;
  final ValueChanged<Access> onChanged;

  @override
  Widget build(BuildContext context) => ShadSelect<Access>(
    initialValue: value,
    options: [
      for (final access in Access.values)
        ShadOption(value: access, child: Text(_access(access))),
    ],
    selectedOptionBuilder: (context, access) => Text(_access(access)),
    onChanged: (access) {
      if (access != null && access != value) onChanged(access);
    },
  );
}

/// Picks a team and its access, to link it to an organization.
class LinkTeamDialog extends StatefulWidget {
  const LinkTeamDialog({super.key, required this.teams});

  final Future<Result<List<TeamSummary>>> Function() teams;

  @override
  State<LinkTeamDialog> createState() => _LinkTeamDialogState();
}

class _LinkTeamDialogState extends State<LinkTeamDialog> {
  Loadable<List<TeamSummary>> _teams = const Loading();
  String? _team;
  Access _access = Access.read;

  @override
  void initState() {
    super.initState();
    _load().ignore();
  }

  Future<void> _load() async {
    setState(() => _teams = const Loading());
    final result = await widget.teams();
    if (!mounted) return;
    setState(
      () => _teams = switch (result) {
        Ok(:final value) => Loaded(value),
        Failure(:final error) => LoadFailed(error),
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    final team = _team;
    return ShadDialog(
      title: const Text(Messages.linkTeam),
      actions: [
        ShadButton.outline(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text(Messages.cancel),
        ),
        ShadButton(
          onPressed: team == null
              ? null
              : () => Navigator.of(context).pop((team, _access)),
          child: const Text(Messages.add),
        ),
      ],
      child: SizedBox(
        width: 360,
        child: LoadableView(
          loadable: _teams,
          onRetry: _load,
          builder: (context, teams) => ShadColumn(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            spacing: 3,
            children: [
              ShadSelect<String>(
                placeholder: const Text(Messages.teams),
                options: [
                  for (final team in teams)
                    ShadOption(value: team.id, child: Text(team.name)),
                ],
                selectedOptionBuilder: (context, id) => Text(
                  teams.where((team) => team.id == id).firstOrNull?.name ?? '',
                ),
                onChanged: (id) => setState(() => _team = id),
              ),
              AccessSelect(
                value: _access,
                onChanged: (access) => setState(() => _access = access),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
