import 'package:flutter/widgets.dart';
import 'package:kanbot/ui/core/messages.dart';
import 'package:shad/shad.dart';

/// Shown while the app asks the server who is signed in.
class LoadingPage extends StatelessWidget {
  const LoadingPage({super.key});

  @override
  Widget build(BuildContext context) => ColoredBox(
    color: ShadTheme.of(context).colorScheme.background,
    child: const Center(
      child: ShadColumn(
        mainAxisSize: MainAxisSize.min,
        spacing: 3,
        children: [ShadSpinner(), Text(Messages.loading)],
      ),
    ),
  );
}
