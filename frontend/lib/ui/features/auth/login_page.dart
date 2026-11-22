import 'package:flutter/widgets.dart';
import 'package:kanbot/config/dependencies.dart';
import 'package:kanbot/data/services/api_exception.dart';
import 'package:kanbot/ui/core/centered_card.dart';
import 'package:kanbot/ui/core/messages.dart';
import 'package:kanbot/ui/features/auth/login_view_model.dart';
import 'package:shad/shad.dart';

/// Sign-in: at the server, through the browser.
class LoginPage extends StatefulWidget {
  const LoginPage({super.key, required this.dependencies, this.error});

  final AppDependencies dependencies;

  /// The server's `error` after a failed web sign-in.
  final String? error;

  @override
  State<LoginPage> createState() => _LoginPageState();
}

class _LoginPageState extends State<LoginPage> {
  late final LoginViewModel _viewModel = LoginViewModel(
    auth: widget.dependencies.auth,
    connection: widget.dependencies.connection,
    serverStore: widget.dependencies.serverStore,
    error: widget.error,
  );

  @override
  void didUpdateWidget(LoginPage old) {
    super.didUpdateWidget(old);
    // Another failed web sign-in (`/login?error=...`) on the same page.
    if (widget.error != old.error) _viewModel.showServerError(widget.error);
  }

  @override
  void dispose() {
    _viewModel.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => CenteredCard(
    title: Messages.signInTitle,
    description: Messages.signInDescription,
    child: ListenableBuilder(
      listenable: _viewModel,
      builder: (context, _) {
        final theme = ShadTheme.of(context);
        final error = _viewModel.error;
        final server = _viewModel.server;
        // The server could not be asked: retry rather than sign in.
        final unreachable =
            error is ApiNetworkException ||
            error is ApiTimeoutException ||
            error is ApiUnavailableException;
        return ShadColumn(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          spacing: 3,
          children: [
            if (server != null && _viewModel.canChangeServer)
              Text(
                // With its port, if any: two servers can share a host.
                '${Messages.server}: ${server.authority}',
                style: theme.textTheme.muted,
              ),
            if (error != null)
              Text(
                Messages.error(error),
                style: theme.textTheme.small.copyWith(
                  color: theme.colorScheme.destructive,
                ),
              ),
            ShadButton(
              onPressed: unreachable
                  ? (_viewModel.busy ? null : _viewModel.retry)
                  : (_viewModel.canSignIn ? _viewModel.signIn : null),
              leading: _viewModel.busy ? const ShadSpinner(size: 16) : null,
              child: Text(unreachable ? Messages.retry : Messages.signIn),
            ),
            if (_viewModel.canChangeServer)
              ShadButton.link(
                // A sign-in still in the browser is for the old server.
                onPressed: _viewModel.canSignIn
                    ? _viewModel.changeServer
                    : null,
                child: const Text(Messages.changeServer),
              ),
          ],
        );
      },
    ),
  );
}
