import 'package:flutter/widgets.dart';
import 'package:kanbot/ui/core/messages.dart';
import 'package:shad/shad.dart';

/// A titled card with a list, and an optional action next to the title.
class Section extends StatelessWidget {
  const Section({
    super.key,
    required this.title,
    required this.children,
    this.action,
  });

  final String title;
  final List<Widget> children;
  final Widget? action;

  @override
  Widget build(BuildContext context) {
    final action = this.action;
    return ShadCard(
      title: Text(title),
      trailing: action,
      child: ShadPadding.only(
        top: 3,
        child: ShadColumn(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          spacing: 2,
          children: children.isEmpty
              ? [const Text(Messages.nothingHere)]
              : children,
        ),
      ),
    );
  }
}

/// One line of a [Section]: a label (a link when [onTap] is set) and its
/// controls.
class ListRow extends StatelessWidget {
  const ListRow({
    super.key,
    required this.label,
    required this.trailing,
    this.onTap,
  });

  final String label;
  final List<Widget> trailing;
  final VoidCallback? onTap;

  @override
  Widget build(BuildContext context) => Wrap(
    alignment: WrapAlignment.spaceBetween,
    crossAxisAlignment: WrapCrossAlignment.center,
    spacing: 2,
    children: [
      if (onTap == null)
        Text(label)
      else
        ShadButton.link(onPressed: onTap, child: Text(label)),
      Wrap(
        spacing: 2,
        crossAxisAlignment: WrapCrossAlignment.center,
        children: trailing,
      ),
    ],
  );
}
