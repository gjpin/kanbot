import 'package:flutter/widgets.dart';
import 'package:kanbot/data/services/api_exception.dart';
import 'package:kanbot/ui/core/messages.dart';
import 'package:kanbot/utils/result.dart';
import 'package:shad/shad.dart';

/// Asks for a name and a slug, then runs [submit] with them. Field errors
/// from the server appear next to their field (AGENTS.md §3). The created
/// value, or `null` when cancelled.
Future<T?> showNameDialog<T>(
  BuildContext context, {
  required String title,
  required String action,
  required Future<Result<T>> Function(String slug, String name) submit,
  String initialName = '',
  String initialSlug = '',
}) => showShadDialog<T>(
  context: context,
  builder: (context) => NameDialog<T>(
    title: title,
    action: action,
    submit: submit,
    initialName: initialName,
    initialSlug: initialSlug,
  ),
);

/// The dialog of [showNameDialog].
class NameDialog<T> extends StatefulWidget {
  const NameDialog({
    super.key,
    required this.title,
    required this.action,
    required this.submit,
    this.initialName = '',
    this.initialSlug = '',
  });

  final String title;
  final String action;
  final Future<Result<T>> Function(String slug, String name) submit;
  final String initialName;
  final String initialSlug;

  @override
  State<NameDialog<T>> createState() => _NameDialogState<T>();
}

class _NameDialogState<T> extends State<NameDialog<T>> {
  late final TextEditingController _name = TextEditingController(
    text: widget.initialName,
  );
  late final TextEditingController _slug = TextEditingController(
    text: widget.initialSlug,
  );
  bool _busy = false;
  Exception? _error;

  @override
  void dispose() {
    _name.dispose();
    _slug.dispose();
    super.dispose();
  }

  String? _fieldError(String pointer) {
    final error = _error;
    if (error is! ApiValidationException) return null;
    for (final field in error.fieldErrors) {
      if (field.pointer == pointer) return Messages.fieldError(field.code);
    }
    return null;
  }

  Future<void> _submit() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    final result = await widget.submit(_slug.text.trim(), _name.text);
    if (!mounted) return;
    switch (result) {
      case Ok(:final value):
        Navigator.of(context).pop(value);
      case Failure(:final error):
        setState(() {
          _busy = false;
          _error = error;
        });
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = ShadTheme.of(context);
    final error = _error;
    final errorStyle = theme.textTheme.small.copyWith(
      color: theme.colorScheme.destructive,
    );
    Widget field(
      String label,
      TextEditingController controller,
      String pointer, {
      String? hint,
    }) {
      final fieldError = _fieldError(pointer);
      return ShadColumn(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        spacing: 1,
        children: [
          Text(label, style: theme.textTheme.small),
          ShadInput(controller: controller, onSubmitted: (_) => _submit()),
          if (hint != null) Text(hint, style: theme.textTheme.muted),
          if (fieldError != null) Text(fieldError, style: errorStyle),
        ],
      );
    }

    return ShadDialog(
      title: Text(widget.title),
      actions: [
        ShadButton.outline(
          onPressed: _busy ? null : () => Navigator.of(context).pop(),
          child: const Text(Messages.cancel),
        ),
        ShadButton(
          onPressed: _busy ? null : _submit,
          child: Text(widget.action),
        ),
      ],
      child: SizedBox(
        width: 360,
        child: ShadColumn(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          spacing: 3,
          children: [
            field(Messages.name, _name, '/name'),
            field(Messages.slug, _slug, '/slug', hint: Messages.slugHint),
            if (error != null && error is! ApiValidationException)
              Text(Messages.error(error), style: errorStyle),
          ],
        ),
      ),
    );
  }
}
