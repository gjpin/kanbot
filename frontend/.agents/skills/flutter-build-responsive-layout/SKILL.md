---
name: flutter-build-responsive-layout
description: Use `LayoutBuilder`, `MediaQuery`, or `Expanded/Flexible` to create a layout that adapts to different screen sizes. Use when you need the UI to look good on both mobile and tablet/desktop form factors.
---
# Implementing Adaptive Layouts

## Contents
- [Space Measurement Guidelines](#space-measurement-guidelines)
- [Widget Sizing and Constraints](#widget-sizing-and-constraints)
- [Device and Orientation Behaviors](#device-and-orientation-behaviors)
- [Workflow: Constructing an Adaptive Layout](#workflow-constructing-an-adaptive-layout)
- [Workflow: Optimizing for Large Screens](#workflow-optimizing-for-large-screens)
- [Examples](#examples)

## Space Measurement Guidelines
Determine the available space accurately to ensure layouts adapt to the app window, not just the physical device.

*   **Use the theme's breakpoints for window-level layout.** `ShadResponsiveBuilder` (or `context.breakpoint`) gives the current band on `ShadTheme.of(context).breakpoints` (`sm` 640, `md` 768, `lg` 1024, ...). Compare with `>=`. Do not invent breakpoint numbers. See the `shad-overview` skill's responsive guide.
*   **Use `MediaQuery.sizeOf(context)`** to get the size of the entire app window.
*   **Use `LayoutBuilder`** to make layout decisions based on the parent widget's allocated space. Evaluate `constraints.maxWidth` to determine the appropriate widget tree to return.
*   **Do not use `MediaQuery.orientationOf` or `OrientationBuilder`** near the top of the widget tree to switch layouts. Device orientation does not accurately reflect the available app window space.
*   **Do not check for hardware types** (e.g., "phone" vs. "tablet"). Flutter apps run in resizable windows, multi-window modes, and picture-in-picture. Base all layout decisions strictly on available window space.

## Widget Sizing and Constraints
Understand and apply Flutter's core layout rule: **Constraints go down. Sizes go up. Parent sets position.**

*   **Distribute Space:** Use `Expanded` and `Flexible` within `ShadRow`, `ShadColumn` (or `Row`, `Column`, `Flex`).
    *   Use `Expanded` to force a child to fill all remaining available space (equivalent to `Flexible` with `fit: FlexFit.tight` and a `flex` factor of 1.0).
    *   Use `Flexible` to allow a child to size itself up to a specific limit while still expanding/contracting. Use the `flex` factor to define the ratio of space consumption among siblings.
*   **Constrain Width:** Prevent widgets from consuming all horizontal space on large screens. Wrap widgets like `GridView` or `ListView` in a `ConstrainedBox` and define a `maxWidth` in the `BoxConstraints`.
*   **Lazy Rendering:** Always use `ListView.builder` or `GridView.builder` when rendering lists with an unknown or large number of items.

## Device and Orientation Behaviors
Ensure the app behaves correctly across all device form factors and input methods.

*   **Do not lock screen orientation.** Locking orientation causes severe layout issues on foldable devices, often resulting in letterboxing (the app centered with black borders). Android large format tiers require both portrait and landscape support.
*   **Fallback for Locked Orientation:** If business requirements strictly mandate a locked orientation, use the `Display API` to retrieve physical screen dimensions instead of `MediaQuery`. `MediaQuery` fails to receive the larger window size in compatibility modes.
*   **Support Multiple Inputs:** Implement support for basic mice, trackpads, and keyboard shortcuts. Ensure touch targets are appropriately sized and keyboard navigation is accessible.

## Workflow: Constructing an Adaptive Layout

Follow this workflow to implement a layout that adapts to the available `BoxConstraints`.

**Task Progress:**
- [ ] Identify the target widget that requires adaptive behavior.
- [ ] Wrap the widget tree in a `LayoutBuilder`.
- [ ] Extract the `constraints.maxWidth` from the builder callback (or use `ShadResponsiveBuilder` when the decision depends on the whole window).
- [ ] Pick the breakpoint from `ShadTheme.of(context).breakpoints` (e.g. `md`).
- [ ] **If `maxWidth >= breakpoint`:** Return a large-screen layout (e.g., a `ShadRow` placing a navigation sidebar and content area side-by-side).
- [ ] **If `maxWidth < breakpoint`:** Return a small-screen layout (e.g., a `ShadColumn` or standard navigation-style approach).
- [ ] Run validator -> resize the application window -> review layout transitions -> fix overflow errors.

## Workflow: Optimizing for Large Screens

Follow this workflow to prevent UI elements from stretching unnaturally on large displays.

**Task Progress:**
- [ ] Identify full-width components (e.g., `ListView`, text blocks, forms).
- [ ] **If optimizing a list:** Convert `ListView.builder` to `GridView.builder` using `SliverGridDelegateWithMaxCrossAxisExtent` to automatically adjust column counts based on window size.
- [ ] **If optimizing a form or text block:** Wrap the component in a `ConstrainedBox`.
- [ ] Apply `BoxConstraints(maxWidth: [optimal_width])` to the `ConstrainedBox`.
- [ ] Wrap the `ConstrainedBox` in a `Center` widget to keep the constrained content centered on large screens.
- [ ] Run validator -> test on desktop/tablet target -> review horizontal stretching -> adjust `maxWidth` or grid extents.

## Examples

### Adaptive Layout using LayoutBuilder
Switches between a narrow and a wide layout based on the space the parent gives it.

```dart
import 'package:flutter/widgets.dart';
import 'package:shad/shad.dart';

class AdaptiveLayout extends StatelessWidget {
  const AdaptiveLayout({super.key, required this.sidebar, required this.content});

  final Widget sidebar;
  final Widget content;

  @override
  Widget build(BuildContext context) {
    final wide = ShadTheme.of(context).breakpoints.md.value;
    return LayoutBuilder(
      builder: (context, constraints) => constraints.maxWidth >= wide
          ? ShadRow(
              children: [
                SizedBox(width: 250, child: sidebar),
                const ShadSeparator.vertical(),
                Expanded(child: content),
              ],
            )
          : content,
    );
  }
}
```

### Window-Level Breakpoints
```dart
ShadResponsiveBuilder(
  builder: (context, breakpoint) =>
      breakpoint >= ShadTheme.of(context).breakpoints.md
          ? const WideLayout()
          : const NarrowLayout(),
)
```

### Constraining Width on Large Screens
Keeps a list readable instead of stretching it across a wide window.

```dart
import 'package:flutter/widgets.dart';
import 'package:shad/shad.dart';

class ConstrainedContent extends StatelessWidget {
  const ConstrainedContent({super.key, required this.items});

  final List<String> items;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 800), // readable width
        child: ListView.builder(
          itemCount: items.length,
          itemBuilder: (context, index) =>
              ShadPadding.all(2, child: Text(items[index])),
        ),
      ),
    );
  }
}
```
