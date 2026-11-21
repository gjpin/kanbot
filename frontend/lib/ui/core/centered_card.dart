import 'package:flutter/widgets.dart';
import 'package:shad/shad.dart';

/// A card in the middle of the screen, for the pages before sign-in.
class CenteredCard extends StatelessWidget {
  const CenteredCard({
    super.key,
    required this.title,
    required this.description,
    required this.child,
  });

  final String title;
  final String description;
  final Widget child;

  @override
  Widget build(BuildContext context) => ColoredBox(
    color: ShadTheme.of(context).colorScheme.background,
    child: Center(
      child: SingleChildScrollView(
        child: ShadPadding.all(
          4,
          child: ShadCard(
            width: 400,
            title: Text(title),
            description: Text(description),
            child: ShadPadding.only(top: 4, child: child),
          ),
        ),
      ),
    ),
  );
}
