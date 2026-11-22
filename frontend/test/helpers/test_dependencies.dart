import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:kanbot/config/dependencies.dart';
import 'package:kanbot/data/repositories/auth_repository.dart';
import 'package:kanbot/data/services/api_connection.dart';
import 'package:kanbot/data/services/server_store.dart';
import 'package:kanbot/data/services/token_store.dart';
import 'package:kanbot/data/services/web_auth.dart';

import 'fake_backend.dart';

/// The server tests talk to.
final Uri testServer = Uri.parse('https://kanbot.example.com/');

/// A [WebAuth] that answers with a scripted redirect, recording the URLs
/// it was asked to open.
class FakeWebAuth implements WebAuth {
  FakeWebAuth(this.answer);

  /// The redirect for the opened URL; throw to simulate a cancel.
  Uri Function(Uri url) answer;
  final List<Uri> opened = [];

  @override
  Future<Uri> authenticate({required Uri url, required String callback}) async {
    opened.add(url);
    return answer(url);
  }
}

/// Dependencies over [backend]. A native app by default, connected to
/// [testServer] unless [connected] is false, with secure storage starting
/// from [storage].
AppDependencies testDependencies({
  FakeBackend? backend,
  bool web = false,
  bool connected = true,
  WebAuth? webAuth,
  Map<String, String> storage = const {},
  List<Uri>? navigations,
}) {
  FlutterSecureStorage.setMockInitialValues(Map.of(storage));
  final server = backend ?? FakeBackend();
  final tokenStore = web ? null : TokenStore();
  final connection = ApiConnection(
    newHttpClient: server.client,
    tokenStore: tokenStore,
  );
  // As in the app: checking a server never carries the session token.
  ApiConnection newConnection() => ApiConnection(newHttpClient: server.client);
  if (connected) connection.connect(testServer);
  return AppDependencies(
    web: web,
    release: false,
    connection: connection,
    auth: AuthRepository(
      connection: connection,
      web: web,
      tokenStore: tokenStore,
      webAuth:
          webAuth ?? FakeWebAuth((_) => throw const SignInCancelledException()),
      nativeRedirect: appSchemeRedirect,
      navigate: (url) => navigations?.add(url),
    ),
    newConnection: newConnection,
    serverStore: web ? null : ServerStore(),
  );
}

/// [testDependencies] with a signed-in user ([me]'s JSON).
Future<AppDependencies> signedIn(
  FakeBackend backend, {
  Map<String, Object?>? user,
  bool web = false,
}) async {
  backend
    ..on('GET', '/auth/config', authConfig())
    ..on('GET', '/me', user ?? me());
  final dependencies = testDependencies(
    backend: backend,
    web: web,
    storage: web ? const {} : const {'auth_token': 'kbs_test'},
  );
  await dependencies.auth.refresh();
  return dependencies;
}
