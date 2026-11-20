---
name: dart-run-static-analysis
description: Run `flutter analyze` to find warnings and errors, and use `dart fix --apply` to resolve mechanical lint issues. Use during development and before declaring a task done.
---
# Analyzing and Fixing Dart Code

## Contents
- [Analysis Configuration](#analysis-configuration)
- [Diagnostics Are Fixed, Never Suppressed](#diagnostics-are-fixed-never-suppressed)
- [Workflow: Executing Static Analysis](#workflow-executing-static-analysis)
- [Workflow: Applying Automated Fixes](#workflow-applying-automated-fixes)

## Analysis Configuration

`frontend/analysis_options.yaml` is already configured and is **read-only for agents**: do not change it without a maintainer's approval. `frontend/AGENTS.md` §11 summarizes it:

- `include: package:flutter_lints/flutter.yaml` (not `recommended.yaml`, which lacks the Flutter rules).
- `strict-inference: true`.
- `no_dynamic_casts` and `no_raw_types` lints, raised to `error`. Since Dart 3.13 these replace the `strict-casts` and `strict-raw-types` options. Do not add those options.
- Many more lints raised to `error`, including `deprecated_member_use`, `unawaited_futures`, `discarded_futures`, `avoid_dynamic_calls`, `use_build_context_synchronously` and `avoid_print`.
- Only generated code (`*.g.dart`, `*.freezed.dart`, `*.mocks.dart`, `lib/src/third_party/**`) and the platform folders are excluded.

## Diagnostics Are Fixed, Never Suppressed

- Never add `// ignore:`, `// ignore_for_file:` or `# ignore:` to hand-written code.
- Never lower a diagnostic's severity, disable a rule or add an `exclude:` entry.
- Never pass `--no-fatal-infos` or `--no-fatal-warnings`.
- Fix the code. If you believe a diagnostic is a false positive, stop and ask a maintainer. Do not work around it.

## Workflow: Executing Static Analysis

**Task Progress:**
- [ ] 1. Run the analyzer from `frontend/`: the `analyze_files` MCP tool if available, otherwise `flutter analyze`. Infos and warnings are fatal by default.
- [ ] 2. Review every diagnostic, including infos.
- [ ] 3. Fix them by hand, or use the Automated Fixes workflow for mechanical ones.
- [ ] 4. Re-run until the output is clean.

## Workflow: Applying Automated Fixes

Use this to resolve deprecated API usages, quick fixes and migrations.

**Task Progress:**
- [ ] 1. Preview with the `dart_fix` MCP tool or `dart fix --dry-run`.
- [ ] 2. Review the proposed fixes. Reject any that change behavior you did not intend.
- [ ] 3. Apply with the `dart_fix` MCP tool or `dart fix --apply`.
- [ ] 4. Format with the `dart_format` MCP tool or `dart format .`.
- [ ] 5. Run the static analysis workflow again.
