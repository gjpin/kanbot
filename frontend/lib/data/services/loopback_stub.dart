/// A free TCP port on 127.0.0.1 for the sign-in redirect (Windows, Linux).
Future<int> freeLoopbackPort() =>
    throw UnsupportedError('no loopback server on this platform');
