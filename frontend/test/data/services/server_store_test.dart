import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:kanbot/data/services/server_store.dart';
import 'package:kanbot/data/services/token_store.dart';

import '../../helpers/test_dependencies.dart';

void main() {
  test('remembers the server next to the token', () async {
    FlutterSecureStorage.setMockInitialValues({
      'auth_token': TokenStore.entry(testServer, 'kbs_x'),
    });
    final store = ServerStore();
    expect(await store.read(release: true), isNull);

    await store.write(Uri.parse('https://kanbot.example.com/'));

    expect(
      await store.read(release: true),
      Uri.parse('https://kanbot.example.com/'),
    );
    expect(await TokenStore().read(server: testServer), 'kbs_x');
    await store.clear();
    expect(await store.read(release: true), isNull);
    expect(await TokenStore().read(server: testServer), 'kbs_x');
  });

  test('forgets a stored server the build does not accept', () async {
    FlutterSecureStorage.setMockInitialValues({
      'server_url': 'http://localhost:3000/',
    });
    final store = ServerStore();
    expect(
      await store.read(release: false),
      Uri.parse('http://localhost:3000/'),
    );
    expect(await store.read(release: true), isNull);
    expect(await TokenStore.defaultStorage.readAll(), isEmpty);
  });
}
