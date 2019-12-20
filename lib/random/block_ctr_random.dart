// See file LICENSE for more information.

library pointycastle.impl.secure_random.block_ctr_random;

import "dart:typed_data";

import "package:pointycastle/api.dart";
import "package:pointycastle/src/registry/registry.dart";
import "package:pointycastle/src/ufixnum.dart";
import "package:pointycastle/src/impl/secure_random_base.dart";

/**
 * An implementation of [SecureRandom] that uses a [BlockCipher] with CTR mode to generate random
 * values.
 */
class BlockCtrRandom extends SecureRandomBase implements SecureRandom {
  /// Intended for internal use.
  static final FactoryConfig FACTORY_CONFIG = new DynamicFactoryConfig.regex(
      SecureRandom,
      r"^(.*)/CTR/PRNG$",
      (_, final Match match) => () {
            String blockCipherName = match.group(1);
            BlockCipher blockCipher = new BlockCipher(blockCipherName);
            return new BlockCtrRandom(blockCipher);
          });

  final BlockCipher cipher;

  Uint8List _input;
  Uint8List _output;
  var _used;

  BlockCtrRandom(this.cipher) {
    _input = new Uint8List(cipher.blockSize);
    _output = new Uint8List(cipher.blockSize);
    _used = _output.length;
  }

  String get algorithmName => "${cipher.algorithmName}/CTR/PRNG";

  void seed(CipherParameters params) {
    _used = _output.length;
    if (params is ParametersWithIV) {
      _input.setAll(0, params.iv);
      cipher.init(true, params.parameters);
    } else {
      cipher.init(true, params);
    }
  }

  int nextUint8() {
    if (_used == _output.length) {
      cipher.processBlock(_input, 0, _output, 0);
      _used = 0;
      _incrementInput();
    }

    return clip8(_output[_used++]);
  }

  void _incrementInput() {
    int offset = _input.length;
    do {
      offset--;
      _input[offset] += 1;
    } while (_input[offset] == 0);
  }
}
