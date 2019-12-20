// See file LICENSE for more information.

library pointycastle.impl.stream_cipher.ctr;

import "package:pointycastle/api.dart";
import "package:pointycastle/stream/sic.dart";
import "package:pointycastle/src/registry/registry.dart";

/// Just an alias to be able to create SIC as CTR
class CTRStreamCipher extends SICStreamCipher {
  /// Intended for internal use.
  static final FactoryConfig FACTORY_CONFIG = new DynamicFactoryConfig.suffix(
      StreamCipher,
      "/CTR",
      (_, final Match match) => () {
            String digestName = match.group(1);
            return new CTRStreamCipher(new BlockCipher(digestName));
          });

  CTRStreamCipher(BlockCipher underlyingCipher) : super(underlyingCipher);
  String get algorithmName => "${underlyingCipher.algorithmName}/CTR";
}
