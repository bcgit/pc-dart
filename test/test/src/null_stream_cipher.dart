// See file LICENSE for more information.

library pointycastle.impl.stream_cipher.test.src.null_stream_cipher;

import "dart:typed_data";

import "package:pointycastle/api.dart";
import "package:pointycastle/src/impl/base_stream_cipher.dart";
import "package:pointycastle/src/registry/registry.dart";

/**
 * An implementation of a null [StreamCipher], that is, a cipher that does not encrypt, neither decrypt. It can be used for
 * testing or benchmarking chaining algorithms.
 */
class NullStreamCipher extends BaseStreamCipher {
  static final FactoryConfig FACTORY_CONFIG =
      new StaticFactoryConfig(StreamCipher, "Null", () => NullStreamCipher());

  String get algorithmName => "Null";

  void reset() {}

  void init(bool forEncryption, CipherParameters params) {}

  void processBytes(
      Uint8List inp, int inpOff, int len, Uint8List out, int outOff) {
    out.setRange(outOff, outOff + len, inp.sublist(inpOff));
  }

  int returnByte(int inp) {
    return inp;
  }
}
