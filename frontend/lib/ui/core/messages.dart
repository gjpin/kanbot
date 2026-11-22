import 'package:kanbot/data/repositories/auth_repository.dart';
import 'package:kanbot/data/services/api_exception.dart';
import 'package:kanbot/data/services/web_auth.dart';

/// Every user-facing string, in one place, so localization (AGENTS.md §9)
/// can replace this file with ARB lookups. English only for now.
abstract final class Messages {
  static const String appName = 'kanbot';

  // Server
  static const String serverTitle = 'Connect to your kanbot server';
  static const String serverDescription =
      'Enter the address your organization gave you, for example '
      'https://kanbot.example.com.';
  static const String serverPlaceholder = 'https://kanbot.example.com';
  static const String connect = 'Connect';
  static const String invalidServer =
      'Enter an https:// address, without anything after the host name '
      'and path.';
  static const String notKanbot =
      'That server did not answer like a kanbot server.';
  static const String changeServer = 'Change server';

  // Sign-in
  static const String signInTitle = 'Sign in';
  static const String signInDescription =
      'You sign in with your organization’s account, in your browser.';
  static const String signIn = 'Sign in';
  static const String signOut = 'Sign out';
  static const String signInCancelled = 'Sign-in was cancelled.';
  static const String signInFailed =
      'The browser could not complete the sign-in. Please try again.';
  static const String loading = 'Loading…';
  static const String retry = 'Try again';

  /// In the browser after a native sign-in (Windows, Linux). It does not
  /// say how the sign-in went: the app does.
  static const String signInLanding =
      'Return to kanbot to continue. You can close this window.';
  static const String unexpectedResponse =
      'The server sent an answer this version of the app does not '
      'understand. The app or the server may need an update.';

  /// The message for a sign-in the server refused, by its `error` code.
  static String signInRefused(String code) => switch (code) {
    'access_denied' => 'Sign-in was cancelled at your identity provider.',
    'no_role' =>
      'Your account is not allowed to use kanbot. Ask your administrator '
          'for access.',
    _ => 'Sign-in failed. Please try again.',
  };

  // Navigation
  static const String organizations = 'Organizations';
  static const String teams = 'Teams';
  static const String audit = 'Audit log';
  static const String settings = 'Settings';

  // Common
  static const String name = 'Name';
  static const String slug = 'Slug';
  static const String slugHint =
      'Lowercase letters, digits and hyphens; used in addresses.';
  static const String save = 'Save';
  static const String rename = 'Rename';
  static const String cancel = 'Cancel';
  static const String create = 'Create';
  static const String delete = 'Delete';
  static const String remove = 'Remove';
  static const String disabledUser = 'Disabled';
  static const String add = 'Add';
  static const String saved = 'Saved.';
  static const String nothingHere = 'Nothing here yet.';
  static const String unnamedUser = 'Unnamed user';
  static const String searchUsers = 'Search people by name';
  static const String noUsersFound = 'No one found.';

  // Organizations
  static const String newOrganization = 'New organization';
  static const String admins = 'Admins';
  static const String addAdmin = 'Add admin';
  static const String linkedTeams = 'Teams with access';
  static const String linkTeam = 'Give a team access';
  static const String read = 'Read';
  static const String write = 'Write';
  static const String openShellWorkspace = 'OpenShell workspace';
  static const String openShellWorkspaceHint =
      'The workspace’s members follow this organization: its admins as '
      'admins, members of teams with write access as users.';
  static const String linkWorkspace = 'Link workspace';
  static const String workspaceName = 'Workspace name';
  static const String notLinked = 'Not linked.';
  static const String unlink = 'Unlink';
  static const String deleteOrganization = 'Delete organization';
  static const String deleteOrganizationConfirm =
      'This removes the organization, its admins and its team links.';

  // Teams
  static const String newTeam = 'New team';
  static const String members = 'Members';
  static const String addMember = 'Add member';
  static const String moreMembers = 'More members';
  static const String moreAdmins = 'More admins';
  static const String moreTeams = 'More teams';
  static const String moreOrganizations = 'More organizations';
  static const String member = 'Member';
  static const String maintainer = 'Maintainer';
  static const String fromIdentityProvider = 'From identity provider';
  static const String idpGroup = 'Identity provider group';
  static const String idpGroupHint =
      'Members of this group are the team’s members. Setting it replaces '
      'the current members.';
  static const String stopSyncing = 'Stop syncing';
  static const String deleteTeam = 'Delete team';
  static const String deleteTeamConfirm =
      'This removes the team, its members and its access to organizations.';

  // Audit
  static const String olderEntries = 'Older entries';

  // Settings
  static const String signedInAs = 'Signed in as';
  static const String platformAdmin = 'Platform admin';
  static const String telemetry = 'Send diagnostics';
  static const String telemetryDescription =
      'Send error reports and performance data to your kanbot server. '
      'Off unless you turn it on.';
  static const String telemetryUnavailable =
      'This server does not collect diagnostics.';
  static const String server = 'Server';

  // Not found
  static const String pageNotFound = 'Page not found';
  static const String goHome = 'Go home';

  /// [at] in local time, to the minute: `2026-11-22 14:05`.
  static String dateTime(DateTime at) {
    final local = at.toLocal();
    String two(int n) => n.toString().padLeft(2, '0');
    return '${local.year}-${two(local.month)}-${two(local.day)} '
        '${two(local.hour)}:${two(local.minute)}';
  }

  /// A user-facing message for a failure. Never shows the response body or
  /// the error code itself (AGENTS.md §3).
  static String error(Exception error) => switch (error) {
    SignInCancelledException() => signInCancelled,
    SignInFailedException() => signInFailed,
    SignInRefusedException(:final code) => signInRefused(code),
    NotKanbotServerException() => notKanbot,
    UnexpectedResponseException() => unexpectedResponse,
    FormatException() => invalidServer,
    ApiUnauthorizedException() => 'Your session has ended. Sign in again.',
    ApiForbiddenException(code: 'account_disabled') =>
      'Your kanbot account has been disabled.',
    ApiForbiddenException() => 'You are not allowed to do that.',
    ApiNotFoundException() => 'That no longer exists, or you cannot see it.',
    ApiConflictException() =>
      'That conflicts with what is there: the name may be taken, or the '
          'members come from the identity provider.',
    ApiValidationException() => 'Some fields are not valid.',
    ApiRateLimitedException() => 'Too many requests. Wait a moment.',
    ApiUnavailableException() || ApiTimeoutException() =>
      'The server is busy or not ready. Try again in a moment.',
    ApiNetworkException() => 'The server cannot be reached.',
    _ => 'Something went wrong.',
  };

  /// The message for a field error code of a `422` response.
  static String fieldError(String code) => switch (code) {
    'required' => 'Required.',
    'too_long' => 'Too long.',
    'invalid' => 'Not valid.',
    'not_found' => 'Not found.',
    _ => 'Not valid.',
  };
}
