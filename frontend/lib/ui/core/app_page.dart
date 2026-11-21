import 'package:flutter/widgets.dart';
import 'package:go_router/go_router.dart';
import 'package:kanbot/domain/models/user.dart';
import 'package:kanbot/routing/router.dart';
import 'package:kanbot/ui/core/loadable.dart';
import 'package:kanbot/ui/core/messages.dart';
import 'package:shad/shad.dart';

/// The frame of every signed-in page: navigation on top, then [child],
/// scrollable and at a readable width.
class AppPage extends StatelessWidget {
  const AppPage({
    super.key,
    required this.user,
    required this.title,
    required this.child,
    this.actions = const [],
  });

  /// The signed-in user: decides which navigation entries exist.
  final User? user;
  final String title;
  final Widget child;
  final List<Widget> actions;

  @override
  Widget build(BuildContext context) {
    final theme = ShadTheme.of(context);
    final user = this.user;
    return ColoredBox(
      color: theme.colorScheme.background,
      child: SafeArea(
        child: ShadColumn(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            ShadPadding.symmetric(
              horizontal: 4,
              vertical: 2,
              child: Wrap(
                spacing: 4,
                crossAxisAlignment: WrapCrossAlignment.center,
                children: [
                  Text(Messages.appName, style: theme.textTheme.large),
                  const _NavLink(
                    label: Messages.organizations,
                    path: Routes.home,
                  ),
                  const _NavLink(label: Messages.teams, path: Routes.teams),
                  if (user != null && user.can(PlatformPermission.viewAudit))
                    const _NavLink(label: Messages.audit, path: Routes.audit),
                  const _NavLink(
                    label: Messages.settings,
                    path: Routes.settings,
                  ),
                ],
              ),
            ),
            const ShadSeparator.horizontal(margin: EdgeInsets.zero),
            Expanded(
              child: SingleChildScrollView(
                child: Center(
                  child: ConstrainedBox(
                    constraints: const BoxConstraints(maxWidth: 880),
                    child: ShadPadding.all(
                      6,
                      child: ShadColumn(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        spacing: 6,
                        children: [
                          Wrap(
                            spacing: 2,
                            runSpacing: 2,
                            alignment: WrapAlignment.spaceBetween,
                            crossAxisAlignment: WrapCrossAlignment.center,
                            children: [
                              Text(title, style: theme.textTheme.h3),
                              Wrap(spacing: 2, children: actions),
                            ],
                          ),
                          child,
                        ],
                      ),
                    ),
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _NavLink extends StatelessWidget {
  const _NavLink({required this.label, required this.path});

  final String label;
  final String path;

  @override
  Widget build(BuildContext context) =>
      ShadButton.ghost(onPressed: () => context.go(path), child: Text(label));
}

/// Shows [loadable]: a spinner, [builder]'s content, or the failure with a
/// retry button.
class LoadableView<T> extends StatelessWidget {
  const LoadableView({
    super.key,
    required this.loadable,
    required this.builder,
    required this.onRetry,
  });

  final Loadable<T> loadable;
  final Widget Function(BuildContext context, T value) builder;
  final VoidCallback onRetry;

  @override
  Widget build(BuildContext context) => switch (loadable) {
    Loading() => const Center(child: ShadSpinner()),
    Loaded(:final value) => builder(context, value),
    LoadFailed(:final error) => ErrorPanel(error: error, onRetry: onRetry),
  };
}

/// A failure, in words the user understands, with an optional retry.
class ErrorPanel extends StatelessWidget {
  const ErrorPanel({super.key, required this.error, this.onRetry});

  final Exception error;
  final VoidCallback? onRetry;

  @override
  Widget build(BuildContext context) {
    final onRetry = this.onRetry;
    return ShadAlert.destructive(
      icon: const Icon(LucideIcons.circleAlert),
      title: Text(Messages.error(error)),
      description: onRetry == null
          ? null
          : Align(
              alignment: Alignment.centerLeft,
              child: ShadButton.outline(
                size: ShadButtonSize.sm,
                onPressed: onRetry,
                child: const Text(Messages.retry),
              ),
            ),
    );
  }
}

/// A short status line under a list or form, for example after saving.
void showMessage(BuildContext context, String message, {bool error = false}) {
  ShadToaster.of(context).show(
    error
        ? ShadToast.destructive(title: Text(message))
        : ShadToast(title: Text(message)),
  );
}

/// Asks before something that cannot be undone. `true` when confirmed.
Future<bool> confirm(
  BuildContext context, {
  required String title,
  required String description,
  required String action,
}) async {
  final confirmed = await showShadDialog<bool>(
    context: context,
    builder: (context) => ShadDialog.alert(
      title: Text(title),
      description: Text(description),
      actions: [
        ShadButton.outline(
          onPressed: () => Navigator.of(context).pop(false),
          child: const Text(Messages.cancel),
        ),
        ShadButton.destructive(
          onPressed: () => Navigator.of(context).pop(true),
          child: Text(action),
        ),
      ],
    ),
  );
  return confirmed ?? false;
}

/// The name to show for a user.
String displayName(UserSummary user) =>
    user.displayName ?? Messages.unnamedUser;
