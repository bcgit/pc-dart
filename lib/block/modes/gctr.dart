// See file LICENSE for more information.

library pointycastle.impl.block_cipher.modes.gctr;

import "dart:typed_data";

import "package:pointycastle/api.dart";
import "package:pointycastle/src/registry/registry.dart";
import "package:pointycastle/src/impl/base_block_cipher.dart";
import "package:pointycastle/src/ufixnum.dart";

/// Implementation of GOST 28147 OFB counter mode (GCTR) on top of a [BlockCipher].
class GCTRBlockCipher extends BaseBlockCipher {
  /// Intended for internal use.
  static final FactoryConfig FACTORY_CONFIG = new DynamicFactoryConfig.suffix(
      BlockCipher,
      "/GCTR",
      (_, final Match match) => () {
            BlockCipher underlying = new BlockCipher(match.group(1));
            return new GCTRBlockCipher(underlying);
          });

  static const C1 = 16843012; //00000001000000010000000100000100
  static const C2 = 16843009; //00000001000000010000000100000001

  final BlockCipher _underlyingCipher;

  Uint8List _IV;
  Uint8List _ofbV;
  Uint8List _ofbOutV;

  bool _firstStep = true;
  int _N3;
  int _N4;

  GCTRBlockCipher(this._underlyingCipher) {
    if (blockSize != 8) {
      throw new ArgumentError(
          "GCTR can only be used with 64 bit block ciphers");
    }

    _IV = new Uint8List(_underlyingCipher.blockSize);
    _ofbV = new Uint8List(_underlyingCipher.blockSize);
    _ofbOutV = new Uint8List(_underlyingCipher.blockSize);
  }

  int get blockSize => _underlyingCipher.blockSize;

  String get algorithmName => "${_underlyingCipher.algorithmName}/GCTR";

  void reset() {
    _ofbV.setRange(0, _IV.length, _IV);
    _underlyingCipher.reset();
  }

  /**
   * Initialise the cipher and, possibly, the initialisation vector (IV).
   * If an IV isn't passed as part of the parameter, the IV will be all zeros.
   * An IV which is too short is handled in FIPS compliant fashion.
  *
   * @param encrypting if true the cipher is initialised for
   *  encryption, if false for decryption. //ignored by this CTR mode
   * @param params the key and other data required by the cipher.
   * @exception IllegalArgumentException if the params argument is
   * inappropriate.
   */
  void init(bool encrypting, CipherParameters params) {
    _firstStep = true;
    _N3 = 0;
    _N4 = 0;

    if (params is ParametersWithIV) {
      ParametersWithIV ivParam = params;
      var iv = ivParam.iv;

      if (iv.length < _IV.length) {
        // prepend the supplied IV with zeros (per FIPS PUB 81)
        var offset = _IV.length - iv.length;
        _IV.fillRange(0, offset, 0);
        _IV.setRange(offset, _IV.length, iv);
      } else {
        _IV.setRange(0, _IV.length, iv);
      }

      reset();

      // if params is null we reuse the current working key.
      if (ivParam.parameters != null) {
        _underlyingCipher.init(true, ivParam.parameters);
      }
    } else {
      // TODO: make this behave in a standard way (as the other modes of operation)
      reset();

      // if params is null we reuse the current working key.
      if (params != null) {
        _underlyingCipher.init(true, params);
      }
    }
  }

  int processBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    if ((inpOff + blockSize) > inp.length) {
      throw new ArgumentError("Input buffer too short");
    }

    if ((outOff + blockSize) > out.length) {
      throw new ArgumentError("Output buffer too short");
    }

    if (_firstStep) {
      _firstStep = false;
      _underlyingCipher.processBlock(_ofbV, 0, _ofbOutV, 0);
      _N3 = _bytesToint(_ofbOutV, 0);
      _N4 = _bytesToint(_ofbOutV, 4);
    }
    _N3 += C2;
    _N4 += C1;
    _intTobytes(_N3, _ofbV, 0);
    _intTobytes(_N4, _ofbV, 4);

    _underlyingCipher.processBlock(_ofbV, 0, _ofbOutV, 0);

    // XOR the ofbV with the plaintext producing the cipher text (and the next input block).
    for (var i = 0; i < blockSize; i++) {
      out[outOff + i] = _ofbOutV[i] ^ inp[inpOff + i];
    }

    // change over the input block.
    var offset = _ofbV.length - blockSize;
    _ofbV.setRange(0, offset, _ofbV.sublist(blockSize));
    _ofbV.setRange(offset, _ofbV.length, _ofbOutV);

    return blockSize;
  }

  int _bytesToint(Uint8List inp, int inpOff) {
    return unpack32(inp, inpOff, Endian.little);
  }

  void _intTobytes(int num, Uint8List out, int outOff) {
    pack32(num, out, outOff, Endian.little);
  }
}
