import 'package:flutter/foundation.dart';

/// A page's ViewModel. Its requests can finish after the page is gone
/// (the user navigated away, a `401` sent them to sign-in, a server switch
/// replaced the page): notifying then would throw, so it is skipped.
abstract class ViewModel extends ChangeNotifier {
  bool _disposed = false;

  /// Whether [dispose] has run.
  bool get disposed => _disposed;

  @override
  void notifyListeners() {
    if (!_disposed) super.notifyListeners();
  }

  @override
  void dispose() {
    _disposed = true;
    super.dispose();
  }
}
