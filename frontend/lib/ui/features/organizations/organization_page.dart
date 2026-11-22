import 'dart:async';

import 'package:flutter/widgets.dart';
import 'package:go_router/go_router.dart';
import 'package:kanbot/config/dependencies.dart';
import 'package:kanbot/data/services/api_exception.dart';
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
    unawaited(_viewModel.load());
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

  /// A delete is under way: the button does nothing meanwhile.
  bool _deleting = false;

  Future<void> _delete() async {
    if (_deleting) return;
    _deleting = true;
    try {
      await _confirmAndDelete();
    } finally {
      _deleting = false;
    }
  }

  Future<void> _confirmAndDelete() async {
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

  Future<void> _linkWorkspace(Organization organization) async {
    await showShadDialog<Organization>(
      context: context,
      builder: (context) => WorkspaceDialog(
        initialName: organization.openShellWorkspace ?? '',
        submit: _viewModel.linkOpenShellWorkspace,
      ),
    );
  }

  Widget _workspaceSection(Organization organization) {
    final canLink = organization.can(
      OrganizationPermission.linkOpenShellWorkspace,
    );
    final workspace = organization.openShellWorkspace;
    return Section(
      title: Messages.openShellWorkspace,
      action: canLink
          ? ShadButton.outline(
              size: ShadButtonSize.sm,
              onPressed: () => _linkWorkspace(organization),
              child: const Text(Messages.linkWorkspace),
            )
          : null,
      children: [
        ListRow(
          label: workspace ?? Messages.notLinked,
          trailing: [
            if (canLink && workspace != null)
              ShadButton.ghost(
                size: ShadButtonSize.sm,
                onPressed: () async =>
                    _report(await _viewModel.unlinkOpenShellWorkspace()),
                child: const Text(Messages.unlink),
              ),
          ],
        ),
      ],
    );
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
                        if (admin.disabled)
                          const ShadBadge.destructive(
                            child: Text(Messages.disabledUser),
                          ),
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
                                key: ValueKey((
                                  link.team.id,
                                  _viewModel.revision,
                                )),
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
              // Shown when linked, or to those who may link it.
              if (value.organization.openShellWorkspace != null ||
                  value.organization.can(
                    OrganizationPermission.linkOpenShellWorkspace,
                  ))
                _workspaceSection(value.organization),
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
    unawaited(_load());
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

/// Asks for an OpenShell workspace's name and links it with [submit]. The
/// server's field error (no such workspace) shows under the field.
class WorkspaceDialog extends StatefulWidget {
  const WorkspaceDialog({
    super.key,
    required this.submit,
    this.initialName = '',
  });

  final Future<Result<Organization>> Function(String workspace) submit;
  final String initialName;

  @override
  State<WorkspaceDialog> createState() => _WorkspaceDialogState();
}

class _WorkspaceDialogState extends State<WorkspaceDialog> {
  late final TextEditingController _name = TextEditingController(
    text: widget.initialName,
  );
  bool _busy = false;
  Exception? _error;

  @override
  void dispose() {
    _name.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (_busy) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    final result = await widget.submit(_name.text.trim());
    if (!mounted) return;
    switch (result) {
      case Ok(:final value):
        Navigator.of(context).pop(value);
      case Failure(:final error):
        setState(() {
          _busy = false;
          _error = error;
        });
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = ShadTheme.of(context);
    final error = _error;
    final message = switch (error) {
      null => null,
      ApiValidationException(:final fieldErrors) when fieldErrors.isNotEmpty =>
        Messages.fieldError(fieldErrors.first.code),
      _ => Messages.error(error),
    };
    return ShadDialog(
      title: const Text(Messages.linkWorkspace),
      actions: [
        ShadButton.outline(
          onPressed: _busy ? null : () => Navigator.of(context).pop(),
          child: const Text(Messages.cancel),
        ),
        ShadButton(
          onPressed: _busy ? null : _submit,
          child: const Text(Messages.save),
        ),
      ],
      child: SizedBox(
        width: 360,
        child: ShadColumn(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          spacing: 1,
          children: [
            Text(Messages.workspaceName, style: theme.textTheme.small),
            ShadInput(controller: _name, onSubmitted: (_) => _submit()),
            Text(Messages.openShellWorkspaceHint, style: theme.textTheme.muted),
            if (message != null)
              Text(
                message,
                style: theme.textTheme.small.copyWith(
                  color: theme.colorScheme.destructive,
                ),
              ),
          ],
        ),
      ),
    );
  }
}
