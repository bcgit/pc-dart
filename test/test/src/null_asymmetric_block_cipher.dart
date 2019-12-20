// See file LICENSE for more information.

library pointycastle.impl.asymmetric_block_cipher.test.null_asymmetric_block_cipher;

import "dart:typed_data";

import "package:pointycastle/api.dart";
import "package:pointycastle/src/registry/registry.dart";
import "package:pointycastle/src/impl/base_asymmetric_block_cipher.dart";

/**
 * An implementation of a null [AsymmetricBlockCipher], that is, a cipher that does not encrypt, neither decrypt. It can be used
 * for testing or benchmarking chaining algorithms.
 */
class NullAsymmetricBlockCipher extends BaseAsymmetricBlockCipher {
  /// Intended for internal use.
  static final FactoryConfig FACTORY_CONFIG = new DynamicFactoryConfig.regex(
      AsymmetricBlockCipher,
      r"^Null$",
      (_, _2) => () {
            return new NullAsymmetricBlockCipher(70, 70);
          });

  final int inputBlockSize;
  final int outputBlockSize;

  NullAsymmetricBlockCipher(this.inputBlockSize, this.outputBlockSize);

  String get algorithmName => "Null";

  void reset() {}

  void init(bool forEncryption, CipherParameters params) {}

  int processBlock(
      Uint8List inp, int inpOff, int len, Uint8List out, int outOff) {
    out.setRange(outOff, outOff + len, inp.sublist(inpOff));
    return len;
  }
}

class NullAsymmetricKey implements AsymmetricKey {}

class NullPublicKey extends NullAsymmetricKey implements PublicKey {}

class NullPrivateKey extends NullAsymmetricKey implements PrivateKey {}
