---
name: flutter-implement-json-serialization
description: Create model classes with `fromJson` and `toJson` methods using `dart:convert`. Use for JSON that does not come from the backend API (local storage, files, platform channels). API models are generated; see `flutter-use-http-package`.
---
# Serializing JSON Manually in Flutter

## Contents
- [Core Guidelines](#core-guidelines)
- [Workflow: Implementing a Serializable Model](#workflow-implementing-a-serializable-model)
- [Workflow: Parsing Stored JSON](#workflow-parsing-stored-json)
- [Examples](#examples)

## Core Guidelines

- **Not for API responses**: models for the backend API are generated from `backend/openapi.json` into `lib/data/api/generated/` (see `flutter-use-http-package`). Never hand-write a model for an API request or response. This skill is for any other JSON.

- **Import `dart:convert`**: Utilize Flutter's built-in `dart:convert` library for manual JSON encoding (`jsonEncode`) and decoding (`jsonDecode`).
- **Enforce Type Safety with patterns**: Match the result of `jsonDecode()` with Dart 3 patterns (`switch` / `if-case`). Never use `as` casts (`json['id'] as int`) or `.cast<...>()` on decoded JSON, and never call methods on `dynamic` (`jsonDecode(body)['data']`). Malformed data must produce a `FormatException`, not a `TypeError`.
- **No payload in exceptions**: the `FormatException` message names the model and field, never the JSON itself (it can contain personal data).
- **Fail loudly on lists**: one malformed item fails the whole list. Never skip it silently.
- **Encapsulate Serialization Logic**: Define plain model classes containing properties corresponding to the JSON structure. Implement a `fromJson` factory constructor and a `toJson` method within the model.
- **Handle Background Parsing**: If parsing large JSON documents (execution time > 16ms), offload the parsing logic to a separate isolate using Flutter's `compute()` function to prevent UI jank.

## Workflow: Implementing a Serializable Model

Use this checklist to implement manual JSON serialization for a data model.

**Task Progress:**
- [ ] Define the plain model class with `final` properties.
- [ ] Implement the `factory Model.fromJson(Object? json)` constructor with a pattern `switch`.
- [ ] Implement the `Map<String, Object?> toJson()` method.
- [ ] Write unit tests for both methods, including malformed input (missing field, wrong type, wrong top-level type).
- [ ] Run validator -> review type mismatch errors -> fix casting logic.

1. **Define the Model**: Create a class with properties matching the JSON keys.
2. **Implement `fromJson`**: Destructure the value with a map pattern. Anything that does not match throws `FormatException`.
3. **Implement `toJson`**: Return a `Map<String, Object?>` mapping the class properties back to their JSON string keys.
4. **Validate**: Execute unit tests to ensure type safety, autocompletion, and compile-time exception handling function correctly.

## Workflow: Parsing Stored JSON

Use this workflow when reading JSON the app stored itself (a file, a cache) or received from a platform channel.

**Task Progress:**
- [ ] Determine parsing strategy (Synchronous vs. Isolate).
- [ ] Decode and map the JSON to the model.

1. **Determine Parsing Strategy**:
   - If parsing a **small payload** (e.g., a single object), parse synchronously on the main thread.
   - If parsing a **large payload** (e.g., an array of thousands of objects), use `compute(parseFunction, text)` to parse in a background isolate.
2. **Decode and Map**: Pass the decoded JSON to your model's `fromJson` constructor.

## Examples

### High-Fidelity Model Implementation

```dart
class User {
  const User({required this.id, required this.name, required this.email});

  factory User.fromJson(Object? json) => switch (json) {
    {'id': final int id, 'name': final String name, 'email': final String email} =>
      User(id: id, name: name, email: email),
    // Names the model, never includes the payload.
    _ => throw const FormatException('Invalid User: missing or mistyped field'),
  };

  final int id;
  final String name;
  final String email;

  Map<String, Object?> toJson() => {'id': id, 'name': name, 'email': email};
}
```

### Synchronous Parsing (Small Payload)

```dart
import 'dart:convert';

/// Reads the draft the app saved earlier. Throws a `FormatException`.
Draft readDraft(String stored) => Draft.fromJson(jsonDecode(stored));
```

### Background Parsing (Large Payload)

```dart
import 'dart:convert';

import 'package:flutter/foundation.dart';

// Top-level, as compute() requires.
List<User> parseUsers(String body) => switch (jsonDecode(body)) {
  // A malformed item throws, failing the whole list.
  final List<Object?> items => [for (final item in items) User.fromJson(item)],
  _ => throw const FormatException('Invalid User list: expected an array'),
};

// Where the cached text is read:
Future<List<User>> readCachedUsers(String cached) =>
    compute(parseUsers, cached);
```

### Unit Test

```dart
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('parses a valid user', () {
    final user = User.fromJson({'id': 1, 'name': 'Ada', 'email': 'ada@example.com'});

    expect(user.id, 1);
    expect(user.name, 'Ada');
    expect(user.email, 'ada@example.com');
  });

  test('rejects a mistyped field', () {
    expect(
      () => User.fromJson({'id': '1', 'name': 'Ada', 'email': 'ada@example.com'}),
      throwsFormatException,
    );
  });

  test('rejects a non-object', () {
    expect(() => User.fromJson([1, 2]), throwsFormatException);
  });
}
```
