// See file LICENSE for more information.

library pointycastle.impl.block_cipher.modes.sic;

import "package:pointycastle/api.dart";
import "package:pointycastle/adapters/stream_cipher_as_block_cipher.dart";
import "package:pointycastle/stream/sic.dart";
import "package:pointycastle/src/registry/registry.dart";

/**
 * See [SICStreamCipher].
 */
class SICBlockCipher extends StreamCipherAsBlockCipher {
  /// Intended for internal use.
  static final FactoryConfig FACTORY_CONFIG = new DynamicFactoryConfig.suffix(
      BlockCipher,
      "/SIC",
      (_, final Match match) => () {
            BlockCipher underlying = new BlockCipher(match.group(1));
            return new SICBlockCipher(
                underlying.blockSize, new SICStreamCipher(underlying));
          });

  SICBlockCipher(int blockSize, StreamCipher underlyingCipher)
      : super(blockSize, underlyingCipher);
}
