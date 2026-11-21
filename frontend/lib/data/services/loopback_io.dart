import 'dart:io';

/// A free TCP port on 127.0.0.1 for the sign-in redirect (Windows, Linux):
/// the operating system picks one, which is released for
/// `flutter_web_auth_2` to listen on.
Future<int> freeLoopbackPort() async {
  final socket = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final port = socket.port;
  await socket.close();
  return port;
}
