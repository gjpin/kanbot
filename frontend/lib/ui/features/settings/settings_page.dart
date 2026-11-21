import 'package:flutter/widgets.dart';
import 'package:kanbot/config/dependencies.dart';
import 'package:kanbot/domain/models/user.dart';
import 'package:kanbot/ui/core/app_page.dart';
import 'package:kanbot/ui/core/messages.dart';
import 'package:kanbot/ui/features/settings/settings_view_model.dart';
import 'package:shad/shad.dart';

/// The signed-in user, the telemetry switch (off by default), signing out,
/// and changing server (native apps).
class SettingsPage extends StatefulWidget {
  const SettingsPage({super.key, required this.dependencies});

  final AppDependencies dependencies;

  @override
  State<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends State<SettingsPage> {
  late final SettingsViewModel _viewModel = SettingsViewModel(
    auth: widget.dependencies.auth,
    connection: widget.dependencies.connection,
    serverStore: widget.dependencies.serverStore,
  );

  @override
  void dispose() {
    _viewModel.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => ListenableBuilder(
    listenable: _viewModel,
    builder: (context, _) {
      final theme = ShadTheme.of(context);
      final user = _viewModel.user;
      final server = _viewModel.server;
      final serverUrl = _viewModel.serverUrl;
      final error = _viewModel.error;
      final telemetryAvailable = server?.telemetryAvailable ?? false;
      return AppPage(
        user: user,
        title: Messages.settings,
        child: ShadColumn(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          spacing: 6,
          children: [
            ShadCard(
              title: const Text(Messages.signedInAs),
              description: Text(
                user == null
                    ? ''
                    : [
                        user.displayName ?? Messages.unnamedUser,
                        if (user.role == PlatformRole.admin)
                          Messages.platformAdmin,
                      ].join(' · '),
              ),
              child: ShadPadding.only(
                top: 3,
                child: Wrap(
                  spacing: 2,
                  runSpacing: 2,
                  children: [
                    ShadButton.outline(
                      onPressed: _viewModel.signOut,
                      child: const Text(Messages.signOut),
                    ),
                    if (_viewModel.canChangeServer)
                      ShadButton.ghost(
                        onPressed: _viewModel.changeServer,
                        child: const Text(Messages.changeServer),
                      ),
                  ],
                ),
              ),
            ),
            ShadCard(
              title: const Text(Messages.telemetry),
              description: Text(
                telemetryAvailable
                    ? Messages.telemetryDescription
                    : Messages.telemetryUnavailable,
              ),
              child: ShadPadding.only(
                top: 3,
                child: ShadColumn(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  spacing: 2,
                  children: [
                    ShadSwitch(
                      value: user?.telemetryOptIn ?? false,
                      enabled: telemetryAvailable && !_viewModel.busy,
                      onChanged: (optIn) =>
                          _viewModel.setTelemetryOptIn(optIn: optIn),
                      label: const Text(Messages.telemetry),
                    ),
                    if (error != null)
                      Text(
                        Messages.error(error),
                        style: theme.textTheme.small.copyWith(
                          color: theme.colorScheme.destructive,
                        ),
                      ),
                  ],
                ),
              ),
            ),
            if (serverUrl != null)
              Text(
                '${Messages.server}: $serverUrl'
                '${server == null ? '' : ' (${server.version})'}',
                style: theme.textTheme.muted,
              ),
          ],
        ),
      );
    },
  );
}
