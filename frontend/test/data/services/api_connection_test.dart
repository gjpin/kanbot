import 'package:flutter_test/flutter_test.dart';
import 'package:kanbot/data/services/api_connection.dart';

import '../../helpers/fake_backend.dart';

void main() {
  test('talks to the server it was connected to', () async {
    final first = FakeBackend()..on('GET', '/health', 'ok');
    final connection = ApiConnection(newHttpClient: first.client);
    var notified = 0;
    connection.addListener(() => notified++);
    expect(connection.isConnected, isFalse);
    expect(connection.baseUrl, isNull);
    expect(() => connection.api, throwsStateError);

    connection.connect(Uri.parse('https://one.example.com/'));
    await connection.api.health.health();
    expect(first.requests.single.url.host, 'one.example.com');
    expect(connection.baseUrl, Uri.parse('https://one.example.com/'));

    connection.connect(Uri.parse('https://two.example.com/'));
    await connection.api.health.health();
    expect(first.requests.last.url.host, 'two.example.com');

    connection.disconnect();
    expect(connection.isConnected, isFalse);
    expect(() => connection.api, throwsStateError);
    expect(notified, 3);
    connection.dispose();
  });

  test('reports 401 answers', () async {
    final backend = FakeBackend()
      ..on('GET', '/me', problem(401, 'unauthorized'), status: 401);
    var unauthorized = 0;
    final connection = ApiConnection(newHttpClient: backend.client)
      ..connect(Uri.parse('https://kanbot.example.com/'));
    connection.onUnauthorized = () => unauthorized++;
    await expectLater(connection.api.users.me(), throwsException);
    expect(unauthorized, 1);
  });
}
