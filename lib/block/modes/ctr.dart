// See file LICENSE for more information.

library pointycastle.impl.block_cipher.modes.ctr;

import "package:pointycastle/api.dart";
import "package:pointycastle/adapters/stream_cipher_as_block_cipher.dart";
import "package:pointycastle/stream/ctr.dart";
import "package:pointycastle/src/registry/registry.dart";

class CTRBlockCipher extends StreamCipherAsBlockCipher {
  /// Intended for internal use.
  static final FactoryConfig FACTORY_CONFIG = new DynamicFactoryConfig.suffix(
      BlockCipher,
      "/CTR",
      (_, final Match match) => () {
            BlockCipher underlying = new BlockCipher(match.group(1));
            return new CTRBlockCipher(
                underlying.blockSize, new CTRStreamCipher(underlying));
          });

  CTRBlockCipher(int blockSize, StreamCipher underlyingCipher)
      : super(blockSize, underlyingCipher);
}
