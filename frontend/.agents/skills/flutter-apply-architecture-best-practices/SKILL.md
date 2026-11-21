---
name: flutter-apply-architecture-best-practices
description: Architects a Flutter application using the recommended layered approach (UI, Logic, Data). Use when structuring a new project or refactoring for scalability.
---
# Architecting Flutter Applications

## Contents
- [Architectural Layers](#architectural-layers)
- [Project Structure](#project-structure)
- [Workflow: Implementing a New Feature](#workflow-implementing-a-new-feature)
- [Examples](#examples)

## Architectural Layers

Enforce strict Separation of Concerns by dividing the application into distinct layers. Never mix UI rendering with business logic or data fetching.

### UI Layer (Presentation)
Implement the MVVM (Model-View-ViewModel) pattern to manage UI state and logic.
*   **Views:** Write reusable, lean widgets. Restrict logic in Views to UI-specific operations (e.g., animations, layout constraints, simple routing). Pass all required data from the ViewModel.
*   **ViewModels:** Manage UI state and handle user interactions. Extend `ChangeNotifier` (or use `Listenable`) to expose state. Expose immutable state snapshots to the View. Inject Repositories into ViewModels via the constructor.

### Data Layer
Implement the Repository pattern to isolate data access logic and create a single source of truth.
*   **Services:** stateless classes that wrap external APIs. The backend API's service is **generated**: `KanbotApi` (`lib/data/api/generated/`, from `backend/openapi.json`, see `flutter-use-http-package`), with `ApiClient` as its transport. Never hand-write a service for a backend endpoint. Write services only for other APIs (local storage, platform plugins).
*   **Repositories:** Consume one or more Services. Transform generated API models into clean Domain Models. Handle caching, offline synchronization, and retry logic. Expose Domain Models to ViewModels; generated types never reach the UI.

### Logic Layer (Domain - Optional)
*   **Use Cases:** Implement this layer only if the application contains complex business logic that clutters the ViewModel, or if logic must be reused across multiple ViewModels. Extract this logic into dedicated Use Case (interactor) classes that sit between ViewModels and Repositories.

## Project Structure

Organize the codebase using a hybrid approach: group UI components by feature, and group Data/Domain components by type.

```text
lib/
├── config/             # API URL, AppDependencies (the services, created once)
├── data/
│   ├── api/generated/  # generated API client and models (never edit)
│   ├── repositories/   # Repository implementations
│   └── services/       # ApiClient (transport), TokenStore, local storage wrappers
├── domain/
│   ├── models/         # Clean domain models
│   └── use_cases/      # Optional business logic classes
└── ui/
    ├── core/           # Shared widgets, themes, typography
    └── features/
        └── [feature_name]/
            ├── view_models/
            └── views/
```

## Workflow: Implementing a New Feature

Follow this sequential workflow when adding a new feature to the application. Copy the checklist to track progress.

### Task Progress
- [ ] **Step 1: Define Domain Models.** Create plain immutable classes (`final` fields, `const` constructor) in `lib/domain/models/`. No code-generation packages without approval.
- [ ] **Step 2: Add the Endpoints.** If the backend lacks them, add them there, then regenerate `backend/openapi.json` and the client (`flutter-use-http-package`).
- [ ] **Step 3: Implement Repositories.** Create the Repository to call the generated client and return Domain Models. Test it against the real generated client over `MockClient`.
- [ ] **Step 4: Apply Conditional Logic (Domain Layer).**
  - *If the feature requires complex data transformation or cross-repository logic:* Create a Use Case class.
  - *If the feature is a simple CRUD operation:* Skip to Step 5.
- [ ] **Step 5: Implement the ViewModel.** Create the ViewModel extending `ChangeNotifier`. Inject required Repositories/Use Cases. Expose immutable state and command methods.
- [ ] **Step 6: Implement the View.** Create the UI widget. Use `ListenableBuilder` or `AnimatedBuilder` to listen to ViewModel changes.
- [ ] **Step 7: Inject Dependencies.** Create long-lived services and repositories in `AppDependencies.create` (`lib/config/dependencies.dart`); route builders in `createRouter` pass them to the ViewModel's constructor. No DI container package.
- [ ] **Step 8: Run Validator.** Execute unit tests for the ViewModel and Repository.
  - *Feedback Loop:* Run tests -> Review failures -> Fix logic -> Re-run until passing.

## Examples

### Data Layer: Service and Repository

```dart
import 'package:kanbot/data/services/api_connection.dart';

// 1. Service: the generated `KanbotApi` of the current server
//    (`ApiConnection.api`), sending requests through `ApiClient`, which adds the token, applies the timeout and throws
//    ApiException. (A `users` tag with a `get_user` operation is assumed
//    here for illustration.)

// 2. Repository: single source of truth, returns domain models.
class UserRepository {
  UserRepository({required this._connection});

  final ApiConnection _connection;

  // Keyed by id: one cached user per id, never "the" user.
  final _cache = <int, User>{};

  /// Throws an `ApiException`.
  Future<User> getUser(int id, {bool refresh = false}) async {
    if (!refresh) {
      if (_cache[id] case final cached?) return cached;
    }
    final response = await _connection.api.users.getUser(id: id);
    // Transform the generated API model into the domain model.
    return _cache[id] = User(id: response.id, name: response.fullName);
  }

  /// Called on logout and user switch.
  void clear() => _cache.clear();
}
```

### UI Layer: ViewModel and View

```dart
import 'package:flutter/widgets.dart';
import 'package:kanbot/data/services/api_exception.dart';
import 'package:shad/shad.dart';

// 3. ViewModel: explicit loading/data/error state.
sealed class ProfileState {
  const ProfileState();
}

final class ProfileLoading extends ProfileState {
  const ProfileLoading();
}

final class ProfileLoaded extends ProfileState {
  const ProfileLoaded(this.user);
  final User user;
}

final class ProfileError extends ProfileState {
  const ProfileError(this.message);

  /// User-facing text. Never the exception itself.
  final String message;
}

class ProfileViewModel extends ChangeNotifier {
  ProfileViewModel({required this._userRepository, required this.userId});

  final UserRepository _userRepository;
  final int userId;

  ProfileState _state = const ProfileLoading();
  ProfileState get state => _state;

  Future<void> load({bool refresh = false}) async {
    _state = const ProfileLoading();
    notifyListeners();
    try {
      _state = ProfileLoaded(
        await _userRepository.getUser(userId, refresh: refresh),
      );
    } on ApiException catch (e) {
      // Exhaustive: ApiErrorResponse() catches every other status.
      _state = ProfileError(switch (e) {
        ApiNetworkException() => 'You are offline.',
        ApiTimeoutException() ||
        ApiUnavailableException() ||
        ApiRateLimitedException() => 'The server is busy. Try again.',
        ApiUnauthorizedException() => 'Your session expired.',
        ApiNotFoundException() => 'This profile no longer exists.',
        ApiErrorResponse() => 'Something went wrong.',
      });
    }
    notifyListeners();
  }
}

// 4. View: renders state, forwards events. No logic.
class ProfileView extends StatelessWidget {
  const ProfileView({super.key, required this.viewModel});

  final ProfileViewModel viewModel;

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: viewModel,
      builder: (context, _) => switch (viewModel.state) {
        ProfileLoading() => const Center(child: ShadSpinner()),
        ProfileError(:final message) => ShadAlert.destructive(
          title: Text(message),
        ),
        ProfileLoaded(:final user) => ShadColumn(
          spacing: 2,
          children: [
            Text(user.name),
            ShadButton(
              onPressed: () => viewModel.load(refresh: true),
              child: const Text('Refresh'),
            ),
          ],
        ),
      },
    );
  }
}
```
