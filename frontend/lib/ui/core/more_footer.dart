import 'package:flutter/widgets.dart';
import 'package:kanbot/ui/core/app_page.dart';
import 'package:kanbot/ui/core/paged_view_model.dart';
import 'package:shad/shad.dart';

/// Below a [PagedViewModel]'s list: why the next page failed, and a
/// button labelled [label] for it while there is one. `null` when there
/// is nothing to show.
Widget? moreFooter(PagedViewModel<Object?> viewModel, String label) {
  final error = viewModel.moreError;
  if (error == null && !viewModel.hasMore) return null;
  return ShadColumn(
    crossAxisAlignment: CrossAxisAlignment.stretch,
    spacing: 3,
    children: [
      if (error != null) ErrorPanel(error: error),
      if (viewModel.hasMore)
        ShadButton.outline(
          onPressed: viewModel.loadingMore ? null : viewModel.loadMore,
          child: Text(label),
        ),
    ],
  );
}
