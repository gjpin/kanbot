---
name: flutter-setup-localization
description: Add `flutter_localizations` and `intl`, enable `generate: true` in `pubspec.yaml`, create `l10n.yaml` and wire the generated delegate into `ShadApp.router`. Use when initializing localization support or adding localized strings.
---
# Internationalizing the App

## Contents
- [Core Concepts](#core-concepts)
- [Setup Workflow](#setup-workflow)
- [Implementation Workflow](#implementation-workflow)
- [Advanced Formatting](#advanced-formatting)
- [Examples](#examples)

## Core Concepts
Localized strings live in App Resource Bundle (`.arb`) files. `flutter gen-l10n` (run automatically by `flutter pub get` when `generate: true`) compiles them into an `AppLocalizations` class in the source tree for type-safe access.

`ShadApp` already adds shad's own localizations and `GlobalWidgetsLocalizations`. The app passes only its own delegate. Never add `GlobalMaterialLocalizations` or `GlobalCupertinoLocalizations`: they are deprecated and this project does not use Material or Cupertino.

## Setup Workflow

Adding packages and creating `l10n.yaml` needs approval in the task (`frontend/AGENTS.md` §1, §8).

- [ ] **Task Progress**
  - [ ] 1. Add dependencies.
  - [ ] 2. Enable the `generate` flag.
  - [ ] 3. Create `l10n.yaml`.
  - [ ] 4. Pass the delegate and locales to `ShadApp.router`.
  - [ ] 5. Run `flutter analyze` (see the note below).

### 1. Add Dependencies
```bash
flutter pub add flutter_localizations --sdk=flutter
flutter pub add intl
```
`flutter pub add` writes a caret constraint. Never use `intl: any`. If resolution fails, use the `intl` version that `flutter_localizations` pins.

### 2. Enable Code Generation
```yaml
flutter:
  generate: true
```

### 3. Create `l10n.yaml`
In the `frontend/` root. Do **not** add `synthetic-package`: the `flutter_gen` synthetic package was removed and the key makes the tool exit with an error.
```yaml
arb-dir: lib/l10n
template-arb-file: app_en.arb
output-localization-file: app_localizations.dart
nullable-getter: false
use-escaping: true
```
The generated files are written to `lib/l10n/` and imported from there (`package:kanbot/l10n/app_localizations.dart`). Never import `package:flutter_gen/...`.

### 4. Configure the App Entry Point
In `lib/main.dart`, pass the app's delegate and supported locales to `ShadApp.router`. Do **not** use the generated `AppLocalizations.localizationsDelegates` list: it includes the Material and Cupertino delegates.

```dart
import 'package:kanbot/l10n/app_localizations.dart';

// ... inside KanbotApp.build
return ShadApp.router(
  title: 'Kanbot',
  theme: AppTheme.light,
  darkTheme: AppTheme.dark,
  themeMode: ShadThemeMode.system,
  routerConfig: router,
  localizationsDelegates: const [AppLocalizations.delegate],
  supportedLocales: AppLocalizations.supportedLocales,
);
```

### 5. Analyzer Note
The generated `app_localizations.dart` still references `GlobalMaterialLocalizations` and `GlobalCupertinoLocalizations` in its `localizationsDelegates` list, and its `// ignore_for_file: type=lint` does not cover `deprecated_member_use`, which is an error in this project. If `flutter analyze` reports it, **stop and ask a maintainer** how to handle the generated file. Never add an `// ignore:` or edit `analysis_options.yaml` yourself.

## Implementation Workflow

### 1. Define ARB Files
*   **New content:** add the string to the template file (`lib/l10n/app_en.arb`) with a description.
*   **Existing content:** update the key in every `.arb` file.
*   All user-facing strings come from ARB files. No hardcoded UI strings.

```json
{
  "helloWorld": "Hello World!",
  "@helloWorld": {
    "description": "The conventional newborn programmer greeting"
  }
}
```

Other locales (e.g. `app_es.arb`):
```json
{
  "helloWorld": "¡Hola Mundo!"
}
```

### 2. Generate Localization Classes
```bash
flutter pub get
```
*Feedback loop:* run → read the output for ARB syntax errors → fix missing commas or mismatched placeholders → re-run.

### 3. Consume Localized Strings
With `nullable-getter: false`, `AppLocalizations.of(context)` is non-nullable. Never add `!`.

```dart
Text(AppLocalizations.of(context).helloWorld)
```

## Advanced Formatting

### Placeholders
```json
"hello": "Hello {userName}",
"@hello": {
  "description": "A message with a single parameter",
  "placeholders": {
    "userName": {
      "type": "String",
      "example": "Bob"
    }
  }
}
```

### Plurals
The `other` case is mandatory.
```json
"nWombats": "{count, plural, =0{no wombats} =1{1 wombat} other{{count} wombats}}",
"@nWombats": {
  "description": "A plural message",
  "placeholders": {
    "count": {
      "type": "num",
      "format": "compact"
    }
  }
}
```

### Selects
```json
"pronoun": "{gender, select, male{he} female{she} other{they}}",
"@pronoun": {
  "description": "A gendered message",
  "placeholders": {
    "gender": {
      "type": "String"
    }
  }
}
```

## Examples

### Widget
```dart
import 'package:flutter/widgets.dart';
import 'package:kanbot/l10n/app_localizations.dart';
import 'package:shad/shad.dart';

class GreetingWidget extends StatelessWidget {
  const GreetingWidget({
    super.key,
    required this.userName,
    required this.notificationCount,
  });

  final String userName;
  final int notificationCount;

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    return ShadColumn(
      spacing: 2,
      children: [
        Text(l10n.hello(userName)),
        Text(l10n.nWombats(notificationCount)),
      ],
    );
  }
}
```
