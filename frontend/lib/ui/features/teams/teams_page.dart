import 'dart:async';

import 'package:flutter/widgets.dart';
import 'package:go_router/go_router.dart';
import 'package:kanbot/config/dependencies.dart';
import 'package:kanbot/domain/models/team.dart';
import 'package:kanbot/domain/models/user.dart';
import 'package:kanbot/routing/router.dart';
import 'package:kanbot/ui/core/app_page.dart';
import 'package:kanbot/ui/core/loadable.dart';
import 'package:kanbot/ui/core/messages.dart';
import 'package:kanbot/ui/core/more_footer.dart';
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
    return ListenableBuilder(
      listenable: _viewModel,
      builder: (context, _) {
        final loadable = _viewModel.teams;
        final teams = switch (loadable) {
          Loaded(:final value) => value,
          _ => const <TeamSummary>[],
        };
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
          itemCount: teams.length,
          itemBuilder: (context, index) {
            final team = teams[index];
            return ShadButton.outline(
              mainAxisAlignment: MainAxisAlignment.start,
              onPressed: () => context.go(Routes.team(team.id)),
              trailing: team.idpGroup == null
                  ? null
                  : const ShadBadge.secondary(
                      child: Text(Messages.fromIdentityProvider),
                    ),
              child: Text(team.name),
            );
          },
          footer: moreFooter(_viewModel, Messages.moreTeams),
          // Loading, a failure, or nothing yet; the teams are built
          // lazily below, as the list can grow long.
          child: switch (loadable) {
            Loaded(value: []) => const Text(Messages.nothingHere),
            Loaded() => const SizedBox.shrink(),
            _ => LoadableView(
              loadable: loadable,
              onRetry: _viewModel.load,
              builder: (context, _) => const SizedBox.shrink(),
            ),
          },
        );
      },
    );
  }
}
