// See file LICENSE for more information.

library pointycastle.impl.block_cipher.modes.ofb;

import "dart:typed_data";

import "package:pointycastle/api.dart";
import "package:pointycastle/src/registry/registry.dart";
import "package:pointycastle/src/impl/base_block_cipher.dart";

/// Implementation of Output FeedBack mode (OFB) on top of a [BlockCipher].
class OFBBlockCipher extends BaseBlockCipher {
  /// Intended for internal use.
  static final FactoryConfig FACTORY_CONFIG = new DynamicFactoryConfig.regex(
      BlockCipher,
      r"^(.+)/OFB-([0-9]+)$",
      (_, final Match match) => () {
            BlockCipher underlying = new BlockCipher(match.group(1));
            int blockSizeInBits = int.parse(match.group(2));
            if ((blockSizeInBits % 8) != 0) {
              throw new RegistryFactoryException.invalid(
                  "Bad OFB block size: $blockSizeInBits (must be a multiple of 8)");
            }
            return new OFBBlockCipher(underlying, blockSizeInBits ~/ 8);
          });

  final int blockSize;

  final BlockCipher _underlyingCipher;

  Uint8List _IV;
  Uint8List _ofbV;
  Uint8List _ofbOutV;

  OFBBlockCipher(this._underlyingCipher, this.blockSize) {
    _IV = new Uint8List(_underlyingCipher.blockSize);
    _ofbV = new Uint8List(_underlyingCipher.blockSize);
    _ofbOutV = new Uint8List(_underlyingCipher.blockSize);
  }

  String get algorithmName =>
      "${_underlyingCipher.algorithmName}/OFB-${blockSize * 8}";

  void reset() {
    _ofbV.setRange(0, _IV.length, _IV);
    _underlyingCipher.reset();
  }

  /**
   * Initialise the cipher and, possibly, the initialisation vector (IV). If an IV isn't passed as part of the parameter, the
   * IV will be all zeros. An IV which is too short is handled in FIPS compliant fashion.
   */
  void init(bool forEncryption, CipherParameters params) {
    if (params is ParametersWithIV) {
      ParametersWithIV ivParam = params;
      var iv = ivParam.iv;

      if (iv.length < _IV.length) {
        // prepend the supplied IV with zeros (per FIPS PUB 81)
        var offset = _IV.length - iv.length;
        _IV.fillRange(0, offset, 0);
        _IV.setAll(offset, iv);
      } else {
        _IV.setRange(0, _IV.length, iv);
      }

      reset();

      // if null it's an IV changed only.
      if (ivParam.parameters != null) {
        _underlyingCipher.init(true, ivParam.parameters);
      }
    } else {
      _underlyingCipher.init(true, params);
    }
  }

  int processBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    if ((inpOff + blockSize) > inp.length) {
      throw new ArgumentError("Input buffer too short");
    }

    if ((outOff + blockSize) > out.length) {
      throw new ArgumentError("Output buffer too short");
    }

    _underlyingCipher.processBlock(_ofbV, 0, _ofbOutV, 0);

    // XOR the ofbV with the plaintext producing the cipher text (and the next input block).
    for (int i = 0; i < blockSize; i++) {
      out[outOff + i] = _ofbOutV[i] ^ inp[inpOff + i];
    }

    // change over the input block.
    var offset = _ofbV.length - blockSize;
    _ofbV.setRange(0, offset, _ofbV.sublist(blockSize));
    _ofbV.setRange(offset, _ofbV.length, _ofbOutV);

    return blockSize;
  }
}
