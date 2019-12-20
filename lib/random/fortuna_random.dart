// See file LICENSE for more information.

library pointycastle.impl.secure_random.fortuna_random;

import "dart:typed_data";

import "package:pointycastle/api.dart";
import "package:pointycastle/block/aes_fast.dart";
import "package:pointycastle/random/auto_seed_block_ctr_random.dart";
import "package:pointycastle/src/registry/registry.dart";

/// An implementation of [SecureRandom] as specified in the Fortuna algorithm.
class FortunaRandom implements SecureRandom {
  static final FactoryConfig FACTORY_CONFIG =
      new StaticFactoryConfig(SecureRandom, "Fortuna", () => FortunaRandom());

  AESFastEngine _aes;
  AutoSeedBlockCtrRandom _prng;

  String get algorithmName => "Fortuna";

  FortunaRandom() {
    _aes = new AESFastEngine();
    _prng = new AutoSeedBlockCtrRandom(_aes, false);
  }

  void seed(covariant KeyParameter param) {
    if (param.key.length != 32) {
      throw new ArgumentError(
          "Fortuna PRNG can only be used with 256 bits keys");
    }

    final iv = new Uint8List(16);
    iv[15] = 1;
    _prng.seed(new ParametersWithIV(param, iv));
  }

  int nextUint8() => _prng.nextUint8();

  int nextUint16() => _prng.nextUint16();

  int nextUint32() => _prng.nextUint32();

  BigInt nextBigInteger(int bitLength) => _prng.nextBigInteger(bitLength);

  Uint8List nextBytes(int count) {
    if (count > 1048576) {
      throw new ArgumentError(
          "Fortuna PRNG cannot generate more than 1MB of random data per invocation");
    }

    return _prng.nextBytes(count);
  }
}
