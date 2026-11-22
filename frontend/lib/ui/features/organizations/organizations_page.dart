import 'dart:async';

import 'package:flutter/widgets.dart';
import 'package:go_router/go_router.dart';
import 'package:kanbot/config/dependencies.dart';
import 'package:kanbot/domain/models/organization.dart';
import 'package:kanbot/domain/models/user.dart';
import 'package:kanbot/routing/router.dart';
import 'package:kanbot/ui/core/app_page.dart';
import 'package:kanbot/ui/core/messages.dart';
import 'package:kanbot/ui/core/name_dialog.dart';
import 'package:kanbot/ui/features/organizations/organizations_view_model.dart';
import 'package:shad/shad.dart';

/// The organizations the user may read; platform admins create them here.
class OrganizationsPage extends StatefulWidget {
  const OrganizationsPage({super.key, required this.dependencies});

  final AppDependencies dependencies;

  @override
  State<OrganizationsPage> createState() => _OrganizationsPageState();
}

class _OrganizationsPageState extends State<OrganizationsPage> {
  late final OrganizationsViewModel _viewModel = OrganizationsViewModel(
    repository: widget.dependencies.organizations,
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
    final created = await showNameDialog<Organization>(
      context,
      title: Messages.newOrganization,
      action: Messages.create,
      submit: _viewModel.create,
    );
    if (created != null && mounted) {
      context.go(Routes.organization(created.id));
    }
  }

  @override
  Widget build(BuildContext context) {
    final user = widget.dependencies.auth.user;
    return AppPage(
      user: user,
      title: Messages.organizations,
      actions: [
        if (user != null && user.can(PlatformPermission.createOrganization))
          ShadButton(
            onPressed: _create,
            leading: const Icon(LucideIcons.plus, size: 16),
            child: const Text(Messages.newOrganization),
          ),
      ],
      child: ListenableBuilder(
        listenable: _viewModel,
        builder: (context, _) => LoadableView(
          loadable: _viewModel.organizations,
          onRetry: _viewModel.load,
          builder: (context, organizations) => organizations.isEmpty
              ? const Text(Messages.nothingHere)
              : ShadColumn(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  spacing: 2,
                  children: [
                    for (final organization in organizations)
                      ShadButton.outline(
                        mainAxisAlignment: MainAxisAlignment.start,
                        onPressed: () =>
                            context.go(Routes.organization(organization.id)),
                        child: Text(organization.name),
                      ),
                  ],
                ),
        ),
      ),
    );
  }
}
