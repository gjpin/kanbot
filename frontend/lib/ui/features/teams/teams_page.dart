import 'dart:async';

import 'package:flutter/widgets.dart';
import 'package:go_router/go_router.dart';
import 'package:kanbot/config/dependencies.dart';
import 'package:kanbot/domain/models/team.dart';
import 'package:kanbot/domain/models/user.dart';
import 'package:kanbot/routing/router.dart';
import 'package:kanbot/ui/core/app_page.dart';
import 'package:kanbot/ui/core/messages.dart';
import 'package:kanbot/ui/core/name_dialog.dart';
import 'package:kanbot/ui/features/teams/teams_view_model.dart';
import 'package:shad/shad.dart';

/// The teams the user may see; organization and platform admins create
/// them here.
class TeamsPage extends StatefulWidget {
  const TeamsPage({super.key, required this.dependencies});

  final AppDependencies dependencies;

  @override
  State<TeamsPage> createState() => _TeamsPageState();
}

class _TeamsPageState extends State<TeamsPage> {
  late final TeamsViewModel _viewModel = TeamsViewModel(
    repository: widget.dependencies.teams,
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

  Future<void> _create() async {
    final created = await showNameDialog<Team>(
      context,
      title: Messages.newTeam,
      action: Messages.create,
      submit: _viewModel.create,
    );
    if (created != null && mounted) context.go(Routes.team(created.id));
  }

  @override
  Widget build(BuildContext context) {
    final user = widget.dependencies.auth.user;
    return AppPage(
      user: user,
      title: Messages.teams,
      actions: [
        if (user != null && user.can(PlatformPermission.createTeam))
          ShadButton(
            onPressed: _create,
            leading: const Icon(LucideIcons.plus, size: 16),
            child: const Text(Messages.newTeam),
          ),
      ],
      child: ListenableBuilder(
        listenable: _viewModel,
        builder: (context, _) => LoadableView(
          loadable: _viewModel.teams,
          onRetry: _viewModel.load,
          builder: (context, teams) => teams.isEmpty
              ? const Text(Messages.nothingHere)
              : ShadColumn(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  spacing: 2,
                  children: [
                    for (final team in teams)
                      ShadButton.outline(
                        mainAxisAlignment: MainAxisAlignment.start,
                        onPressed: () => context.go(Routes.team(team.id)),
                        trailing: team.idpGroup == null
                            ? null
                            : const ShadBadge.secondary(
                                child: Text(Messages.fromIdentityProvider),
                              ),
                        child: Text(team.name),
                      ),
                  ],
                ),
        ),
      ),
    );
  }
}
