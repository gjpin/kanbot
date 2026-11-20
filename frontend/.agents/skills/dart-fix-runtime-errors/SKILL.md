---
name: dart-fix-runtime-errors
description: Uses get_runtime_errors and lsp to fetch an active stack trace, locate the failing line, apply a fix, and verify resolution via hot_reload.
---
# Resolving Dart Static Analysis Errors

## Contents
- [Core Concepts & Guidelines](#core-concepts--guidelines)
  - [Type System & Soundness](#type-system--soundness)
  - [Null Safety](#null-safety)
  - [Error Handling](#error-handling)
- [Workflows](#workflows)
  - [Workflow: Static Analysis Resolution](#workflow-static-analysis-resolution)
- [Examples](#examples)

## Core Concepts & Guidelines

### Type System & Soundness
Enforce Dart's sound type system to prevent runtime invalid states.

*   **Method Overrides:** Maintain sound return types (covariant) and parameter types (contravariant). Never tighten a parameter type in a subclass unless explicitly marked with the `covariant` keyword.
*   **Generics & Collections:** Add explicit type annotations to generic classes (e.g., `List<T>`, `Map<K, V>`). Never assign a `List<dynamic>` to a typed list (e.g., `List<Cat>`).
*   **Downcasting:** Avoid downcasts from `dynamic` and `Object?`. Use patterns or `is` checks, which handle the mismatch, instead of `as`, which throws `TypeError`. Never use `as` on decoded JSON or other untrusted data.
*   **Strict Casts:** This project enables the `no_dynamic_casts` and `no_raw_types` lints as errors (they replace the `strict-casts` and `strict-raw-types` options since Dart 3.13). `analysis_options.yaml` is already configured; do not change it.

### Null Safety
Eliminate static errors related to null safety by correctly managing variable initialization and nullability.

*   **Modifiers:** Apply `?` for nullable types, `!` for null assertions, and `required` for named parameters that cannot be null.
*   **Initialization:** Fix "must be initialized" errors by initializing the variable (in the declaration, an initializer list or the constructor) or by making it nullable and handling `null`. Do not add `late` to silence the error: it only moves the failure to runtime. `late final x = expr;` (lazy initialization with an initializer) is fine.
*   **Wildcards:** Use the `_` wildcard variable (Dart 3.7+) for non-binding local variables or parameters to avoid unused variable warnings.

### Error Handling
Distinguish between recoverable exceptions and unrecoverable errors.

*   **Catching:** Catch `Exception` subtypes for recoverable failures.
*   **Errors:** Never explicitly catch `Error` or its subtypes (e.g., `TypeError`, `ArgumentError`). Errors indicate programming bugs that must be fixed, not caught. Enforce this by enabling the `avoid_catching_errors` linter rule.
*   **Rethrowing:** Use `rethrow` inside a `catch` block to propagate an exception while preserving its original stack trace.

## Workflows

### Workflow: Static Analysis Resolution

Use this sequential workflow to identify, fix, and verify static analysis errors in a Dart project. Copy the checklist to track your progress.

**Task Progress:**
- [ ] 1. Run static analyzer.
- [ ] 2. Apply automated fixes.
- [ ] 3. Resolve remaining errors manually.
- [ ] 4. Verify fixes (Feedback Loop).

**1. Run static analyzer**
Execute the Dart analyzer to identify all static errors in the target directory or file.
```bash
flutter analyze   # infos and warnings are fatal by default
```

**2. Apply automated fixes**
Use the `dart fix` tool to automatically resolve standard linting and analysis issues.
```bash
# Preview changes
dart fix --dry-run
# Apply changes
dart fix --apply
```

**3. Resolve remaining errors manually**
Review the remaining analyzer output and apply conditional logic based on the error type:

*   **If the error is a Null Safety issue (e.g., "Property cannot be accessed on a nullable receiver"):**
    *   Verify if the variable can logically be null.
    *   If yes, use optional chaining (`?.`) or provide a fallback (`??`).
    *   If no, initialize it where it is declared or in the constructor. Do not add `late` or `!` to silence the error.
*   **If the error is a Type Mismatch (e.g., "The argument type 'List<dynamic>' can't be assigned..."):**
    *   Trace the variable's initialization.
    *   Add explicit generic type annotations to the instantiation (e.g., `<int>[]` instead of `[]`).
*   **If the error is an Invalid Override (e.g., "The parameter type doesn't match the overridden method"):**
    *   Widen the parameter type to match the superclass, OR
    *   Add the `covariant` keyword to the parameter if tightening the type is intentionally required by the domain logic.

**4. Verify fixes (Feedback Loop)**
Run the validator. Review errors. Fix.
```bash
flutter analyze
flutter test
```
*   **If `flutter analyze` reports errors:** Return to Step 3.
*   **If `flutter test` fails with a `TypeError`:** An `as` cast or a `!` failed, or a `late` variable was read before it was set. Replace the cast with a pattern or `is` check, and initialize the variable instead of using `late`.

## Examples

### Example: Fixing Dynamic List Assignments
**Input (Fails Static Analysis):**
```dart
void printInts(List<int> a) => print(a);

void main() {
  final list = []; // Inferred as List<dynamic>
  list.add(1);
  list.add(2);
  printInts(list); // Error: List<dynamic> can't be assigned to List<int>
}
```

**Output (Passes Static Analysis):**
```dart
void printInts(List<int> a) => print(a);

void main() {
  final list = <int>[]; // Explicitly typed
  list.add(1);
  list.add(2);
  printInts(list);
}
```

### Example: Fixing Method Overrides (Contravariance)
**Input (Fails Static Analysis):**
```dart
class Animal {
  void chase(Animal a) {}
}

class Cat extends Animal {
  @override
  void chase(Mouse a) {} // Error: Tightening parameter type
}
```

**Output (Passes Static Analysis):**
```dart
class Animal {
  void chase(Animal a) {}
}

class Cat extends Animal {
  @override
  void chase(covariant Mouse a) {} // Explicitly marked covariant
}
```

### Example: Fixing an Uninitialized Field
**Input (Fails Static Analysis):**
```dart
class Thermometer {
  String temperature; // Error: Non-nullable instance field must be initialized

  void read() {
    temperature = '20C';
  }
}
```

**Output (Passes Static Analysis):** initialize it, or make it nullable if "no reading yet" is a real state. Not `late`, which only moves the error to runtime.
```dart
class Thermometer {
  String? temperature; // null until the first reading

  void read() {
    temperature = '20C';
  }
}
```
