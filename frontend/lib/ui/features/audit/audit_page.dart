import 'dart:async';

import 'package:flutter/widgets.dart';
import 'package:kanbot/config/dependencies.dart';
import 'package:kanbot/domain/models/audit.dart';
import 'package:kanbot/ui/core/app_page.dart';
import 'package:kanbot/ui/core/loadable.dart';
import 'package:kanbot/ui/core/messages.dart';
import 'package:kanbot/ui/features/audit/audit_view_model.dart';
import 'package:shad/shad.dart';

/// Who changed which organization or team, and the policies that allowed
/// it. Platform admins only (the server refuses everyone else).
class AuditPage extends StatefulWidget {
  const AuditPage({super.key, required this.dependencies});

  final AppDependencies dependencies;

  @override
  State<AuditPage> createState() => _AuditPageState();
}

class _AuditPageState extends State<AuditPage> {
  late final AuditViewModel _viewModel = AuditViewModel(
    users: widget.dependencies.users,
  );

  @override
  void initState() {
    super.initState();
    unawaited(_viewModel.load());
  }

  @override
  void dispose() {
    _viewModel.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = ShadTheme.of(context);
    return ListenableBuilder(
      listenable: _viewModel,
      builder: (context, _) {
        final loadable = _viewModel.entries;
        final entries = switch (loadable) {
          Loaded(:final value) => value,
          _ => const <AuditEntry>[],
        };
        final moreError = _viewModel.moreError;
        return AppPage(
          user: widget.dependencies.auth.user,
          title: Messages.audit,
          itemCount: entries.length,
          itemBuilder: (context, index) {
            final entry = entries[index];
            return ShadCard(
              title: Text(entry.action),
              description: Text(
                '${Messages.dateTime(entry.at)} · ${displayName(entry.actor)}',
              ),
              child: Text(
                '${entry.targetType} ${entry.targetId}\n'
                '${entry.policyIds.join(', ')}',
                style: theme.textTheme.muted,
              ),
            );
          },
          footer: moreError != null || _viewModel.hasMore
              ? ShadColumn(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  spacing: 3,
                  children: [
                    if (moreError != null) ErrorPanel(error: moreError),
                    if (_viewModel.hasMore)
                      ShadButton.outline(
                        onPressed: _viewModel.loadingMore
                            ? null
                            : _viewModel.loadMore,
                        child: const Text(Messages.olderEntries),
                      ),
                  ],
                )
              : null,
          // Loading, a failure, or nothing yet; the entries are built
          // lazily below, as the list can grow long.
          child: switch (loadable) {
            Loaded(value: []) => const Text(Messages.nothingHere),
            Loaded() => const SizedBox.shrink(),
            _ => LoadableView(
              loadable: loadable,
              onRetry: _viewModel.load,
              builder: (context, _) => const SizedBox.shrink(),
            ),
          },
        );
      },
    );
  }
}
