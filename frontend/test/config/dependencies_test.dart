import 'package:flutter_test/flutter_test.dart';

import '../helpers/fake_backend.dart';
import '../helpers/test_dependencies.dart';

void main() {
  test('the web app knows its server before the first frame', () {
    final dependencies = testDependencies(
      backend: FakeBackend(),
      web: true,
      connected: false,
    );
    expect(dependencies.connection.isConnected, isFalse);

    dependencies.connectWeb(
      Uri.parse('https://kanbot.example.com:8443/organizations/x?y=1'),
    );

    expect(
      dependencies.connection.baseUrl,
      Uri.parse('https://kanbot.example.com:8443/'),
    );
  });

  test('start connects the web app once, and loads the session', () async {
    final backend = FakeBackend()
      ..on('GET', '/auth/config', authConfig())
      ..on('GET', '/me', me());
    final dependencies = testDependencies(
      backend: backend,
      web: true,
      connected: false,
    );
    final page = Uri.parse('https://kanbot.example.com/');
    dependencies.connectWeb(page);
    await dependencies.start(page: page);
    expect(dependencies.auth.user?.displayName, 'Alice');
  });
}
