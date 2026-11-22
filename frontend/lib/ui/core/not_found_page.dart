import 'package:flutter/widgets.dart';
import 'package:go_router/go_router.dart';
import 'package:kanbot/routing/router.dart';
import 'package:kanbot/ui/core/messages.dart';
import 'package:shad/shad.dart';

/// Shown for unknown or invalid routes, including deep links.
class NotFoundPage extends StatelessWidget {
  const NotFoundPage({super.key});

  @override
  Widget build(BuildContext context) {
    final theme = ShadTheme.of(context);
    return ColoredBox(
      color: theme.colorScheme.background,
      child: Center(
        child: ShadColumn(
          mainAxisSize: .min,
          spacing: 4,
          children: [
            Text(Messages.pageNotFound, style: theme.textTheme.h3),
            ShadButton(
              onPressed: () => context.go(Routes.home),
              child: const Text(Messages.goHome),
            ),
          ],
        ),
      ),
    );
  }
}
