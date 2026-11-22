import 'package:flutter/widgets.dart';
import 'package:kanbot/data/repositories/users_repository.dart';
import 'package:kanbot/domain/models/user.dart';
import 'package:kanbot/ui/core/app_page.dart';
import 'package:kanbot/ui/core/loadable.dart';
import 'package:kanbot/ui/core/messages.dart';
import 'package:kanbot/utils/result.dart';
import 'package:shad/shad.dart';

/// Lets the user find someone by name. The one picked, or `null`.
Future<UserSummary?> pickUser(
  BuildContext context, {
  required UsersRepository users,
  required String title,
}) => showShadDialog<UserSummary>(
  context: context,
  builder: (context) => UserPicker(users: users, title: title),
);

/// The dialog of [pickUser].
class UserPicker extends StatefulWidget {
  const UserPicker({super.key, required this.users, required this.title});

  final UsersRepository users;
  final String title;

  @override
  State<UserPicker> createState() => _UserPickerState();
}

class _UserPickerState extends State<UserPicker> {
  final TextEditingController _query = TextEditingController();
  Loadable<List<UserSummary>>? _results;

  /// The latest search: an older one answering late is ignored.
  int _searches = 0;

  @override
  void dispose() {
    _query.dispose();
    super.dispose();
  }

  Future<void> _search() async {
    final search = ++_searches;
    setState(() => _results = const Loading());
    final result = await widget.users.search(_query.text.trim());
    if (!mounted || search != _searches) return;
    setState(
      () => _results = switch (result) {
        Ok(:final value) => Loaded(value),
        Failure(:final error) => LoadFailed(error),
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    final results = _results;
    return ShadDialog(
      title: Text(widget.title),
      actions: [
        ShadButton.outline(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text(Messages.cancel),
        ),
      ],
      child: SizedBox(
        width: 360,
        child: ShadColumn(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          spacing: 3,
          children: [
            ShadInput(
              controller: _query,
              placeholder: const Text(Messages.searchUsers),
              autofocus: true,
              onSubmitted: (_) => _search(),
              trailing: ShadIconButton.ghost(
                icon: const Icon(LucideIcons.search, size: 16),
                onPressed: _search,
              ),
            ),
            if (results != null)
              LoadableView(
                loadable: results,
                onRetry: _search,
                builder: (context, users) => users.isEmpty
                    ? const Text(Messages.noUsersFound)
                    // A search can find many people: the list scrolls
                    // inside the dialog.
                    : ConstrainedBox(
                        constraints: const BoxConstraints(maxHeight: 320),
                        child: ListView.builder(
                          shrinkWrap: true,
                          itemCount: users.length,
                          itemBuilder: (context, index) => ShadButton.ghost(
                            mainAxisAlignment: MainAxisAlignment.start,
                            onPressed: () =>
                                Navigator.of(context).pop(users[index]),
                            child: Text(displayName(users[index])),
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
