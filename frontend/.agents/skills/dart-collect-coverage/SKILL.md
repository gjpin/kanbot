---
name: dart-collect-coverage
description: Collect test coverage with `flutter test --coverage`, read the LCOV report and close the gaps with tests. Use when checking that a change did not lower coverage.
---
# Test Coverage

## Contents
- [Rules](#rules)
- [Workflow: Generating and Reading Coverage](#workflow-generating-and-reading-coverage)
- [Workflow: Closing a Coverage Gap](#workflow-closing-a-coverage-gap)

## Rules

- Coverage must not go down (`frontend/AGENTS.md` §7). CI does not enforce a threshold yet, so check it yourself.
- **Never use `// coverage:ignore-line`, `// coverage:ignore-start` / `ignore-end` or `// coverage:ignore-file`.** Missing coverage is fixed by writing tests, never by hiding code from the report.
- Generated code (`*.g.dart`, `*.mocks.dart`) is not written by hand; it does not need its own tests.
- No extra package is needed. `flutter test --coverage` is built in; do not add `package:coverage`.

## Workflow: Generating and Reading Coverage

**Task Progress:**
- [ ] 1. Run all tests with coverage from `frontend/`.
- [ ] 2. Compare with the coverage before your change.
- [ ] 3. Find uncovered lines in the files you changed.

### 1. Run tests with coverage
```bash
flutter test --coverage
```
This writes `coverage/lcov.info` (git-ignored).

### 2. Summarize
Line coverage per file, from the LCOV records (`SF:` = file, `LF:` = lines found, `LH:` = lines hit):
```bash
awk -F: '/^SF:/{f=$2} /^LF:/{lf=$2} /^LH:/{printf "%5.1f%%  %s\n", ($2/lf)*100, f}' coverage/lcov.info | sort -n
```
Total:
```bash
awk -F: '/^LF:/{f+=$2} /^LH:/{h+=$2} END{printf "%.1f%%\n", h/f*100}' coverage/lcov.info
```
Run the same commands on the base branch (`git stash`, or a separate worktree) to compare.

### 3. Find uncovered lines
`DA:<line>,0` records are lines that never ran:
```bash
awk -F'[:,]' '/^SF:/{f=$2} /^DA:/ && $3==0 {print f ":" $2}' coverage/lcov.info | grep lib/path/to/changed_file.dart
```
If `genhtml` (from `lcov`) is installed, `genhtml coverage/lcov.info -o coverage/html` gives a browsable report.

## Workflow: Closing a Coverage Gap

**Task Progress:**
- [ ] 1. For each uncovered line in a changed file, identify the behavior it implements (often an error path: timeout, 401, 503, malformed JSON).
- [ ] 2. Write a test through the public interface that exercises that behavior and asserts its result. A test that only runs the line without checking the outcome does not count.
- [ ] 3. Re-run `flutter test --coverage` and confirm the lines are now hit.
- [ ] 4. If a line truly cannot be reached, it is dead code: remove it, or ask a maintainer. Do not ignore it.
