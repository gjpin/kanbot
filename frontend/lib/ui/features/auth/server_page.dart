import 'package:flutter/widgets.dart';
import 'package:kanbot/config/dependencies.dart';
import 'package:kanbot/data/services/server_store.dart';
import 'package:kanbot/ui/core/centered_card.dart';
import 'package:kanbot/ui/core/messages.dart';
import 'package:kanbot/ui/features/auth/server_view_model.dart';
import 'package:shad/shad.dart';

/// Asks a native app's user which kanbot server to use (HTTPS only).
class ServerPage extends StatefulWidget {
  const ServerPage({super.key, required this.dependencies});

  final AppDependencies dependencies;

  @override
  State<ServerPage> createState() => _ServerPageState();
}

class _ServerPageState extends State<ServerPage> {
  late final ServerViewModel _viewModel = ServerViewModel(
    connection: widget.dependencies.connection,
    newConnection: widget.dependencies.newConnection,
    auth: widget.dependencies.auth,
    store: widget.dependencies.serverStore ?? ServerStore(),
    release: widget.dependencies.release,
  );
  final TextEditingController _url = TextEditingController();

  @override
  void dispose() {
    _viewModel.dispose();
    _url.dispose();
    super.dispose();
  }

  Future<void> _connect() => _viewModel.connect(_url.text);

  @override
  Widget build(BuildContext context) => CenteredCard(
    title: Messages.serverTitle,
    description: Messages.serverDescription,
    child: ListenableBuilder(
      listenable: _viewModel,
      builder: (context, _) {
        final error = _viewModel.error;
        return ShadColumn(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          spacing: 3,
          children: [
            ShadInput(
              controller: _url,
              placeholder: const Text(Messages.serverPlaceholder),
              keyboardType: TextInputType.url,
              autocorrect: false,
              onSubmitted: (_) => _connect(),
            ),
            if (error != null)
              Text(
                error is FormatException
                    ? Messages.invalidServer
                    : Messages.error(error),
                style: ShadTheme.of(context).textTheme.small.copyWith(
                  color: ShadTheme.of(context).colorScheme.destructive,
                ),
              ),
            ShadButton(
              onPressed: _viewModel.busy ? null : _connect,
              leading: _viewModel.busy ? const ShadSpinner(size: 16) : null,
              child: const Text(Messages.connect),
            ),
          ],
        );
      },
    ),
  );
}
