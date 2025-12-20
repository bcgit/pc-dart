@JS()
import 'dart:js_interop';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/src/impl/entropy.dart';

import 'node_crypto.dart';
import 'platform_check.dart';

class PlatformWeb extends Platform {
  static final PlatformWeb instance = PlatformWeb();
  static bool useBuiltInRng = !isNodeDart2JS;

  const PlatformWeb();

  @override
  bool get isNative => false;

  @override
  String get platform => 'web';

  @override
  EntropySource platformEntropySource() =>
      useBuiltInRng ? _JsBuiltInEntropySource() : _JsNodeEntropySource();
}

// Uses the built in entropy source
class _JsBuiltInEntropySource implements EntropySource {
  final _src = Random.secure();

  @override
  Uint8List getBytes(int len) {
    final Uint8List bytes = Uint8List(len);
    for (int i = 0; i < len; i++) {
      bytes[i] = _src.nextInt(256);
    }
    return bytes;
  }
}

///
class _JsNodeEntropySource implements EntropySource {
  @override
  Uint8List getBytes(int len) => NodeCrypto.randomBytes(len).toDart;
}

Platform getPlatform() => PlatformWeb.instance;
