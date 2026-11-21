/// The application ID on every platform: Android `applicationId`, the
/// Apple bundle identifier, Linux `APPLICATION_ID`. Its reverse-DNS form is
/// also the app's URL scheme for the login handoff (AGENTS.md §2).
const String applicationId = 'dev.sideral.kanbot';

/// Where the kanbot backend hands a native sign-in back to the app on
/// Android, iOS and macOS (the backend's `APP_REDIRECT_URI`). Windows and
/// Linux use a loopback URL instead.
const String appRedirectUri = '$applicationId:/auth/done';
