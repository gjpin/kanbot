import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:kanbot/data/services/token_store.dart';

void main() {
  late TokenStore store;

  setUp(() {
    // In-memory platform implementation provided by flutter_secure_storage.
    FlutterSecureStorage.setMockInitialValues({});
    store = TokenStore();
  });

  test('is empty when signed out', () async {
    expect(await store.read(), isNull);
  });

  test('reads back the written token', () async {
    await store.write('token-1');
    expect(await store.read(), 'token-1');

    await store.write('token-2');
    expect(await store.read(), 'token-2');
  });

  test('clear removes the token and everything else stored', () async {
    FlutterSecureStorage.setMockInitialValues({'other': 'value'});
    store = TokenStore();
    await store.write('token');

    await store.clear();

    expect(await store.read(), isNull);
    expect(await TokenStore.defaultStorage.readAll(), isEmpty);
  });
}
