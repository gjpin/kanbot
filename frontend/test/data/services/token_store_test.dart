import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:kanbot/data/services/token_store.dart';

void main() {
  final server = Uri.parse('https://kanbot.example.com/');
  final other = Uri.parse('https://other.example.com/');
  late TokenStore store;

  setUp(() {
    // In-memory platform implementation provided by flutter_secure_storage.
    FlutterSecureStorage.setMockInitialValues({});
    store = TokenStore();
  });

  test('is empty when signed out', () async {
    expect(await store.read(server: server), isNull);
  });

  test('reads back the written token', () async {
    await store.write('token-1', server: server);
    expect(await store.read(server: server), 'token-1');

    await store.write('token-2', server: server);
    expect(await store.read(server: server), 'token-2');
  });

  test('gives a token only to the server that issued it', () async {
    await store.write('token-a', server: server);

    expect(await store.read(server: other), isNull);
    expect(
      await store.read(server: Uri.parse('https://kanbot.example.com/v2/')),
      isNull,
    );
    expect(await store.read(server: server), 'token-a');

    await store.write('token-b', server: other);
    expect(await store.read(server: server), isNull, reason: 'replaced');
    expect(await store.read(server: other), 'token-b');
  });

  test('ignores a token stored without its server', () async {
    FlutterSecureStorage.setMockInitialValues({'auth_token': 'kbs_old'});
    store = TokenStore();

    expect(await store.read(server: server), isNull);
  });

  test('clear removes the token and keeps the chosen server', () async {
    FlutterSecureStorage.setMockInitialValues({
      'server_url': 'https://kanbot.example.com/',
    });
    store = TokenStore();
    await store.write('token', server: server);

    await store.clear();

    expect(await store.read(server: server), isNull);
    expect(await TokenStore.defaultStorage.readAll(), {
      'server_url': 'https://kanbot.example.com/',
    });
  });
}
