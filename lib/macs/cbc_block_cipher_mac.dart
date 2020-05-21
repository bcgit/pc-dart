// See file LICENSE for more information.

library pointycastle.impl.mac.cbc_block_cipher_mac;

import "dart:typed_data";

import "package:pointycastle/api.dart";
import "package:pointycastle/src/registry/registry.dart";
import "package:pointycastle/src/impl/base_mac.dart";
import "package:pointycastle/paddings/iso7816d4.dart";
import "package:pointycastle/block/modes/cbc.dart";

/// standard CBC Block Cipher MAC - if no padding is specified the default of
/// pad of zeroes is used.
class CBCBlockCipherMac extends BaseMac {
  static final FactoryConfig FACTORY_CONFIG = new DynamicFactoryConfig.regex(
      Mac,
      r"^(.+)/CBC_CMAC(/(.+))?$",
      (_, final Match match) => () {
            BlockCipher cipher = new BlockCipher(match.group(1));
            Padding padding = match.groupCount >= 3 &&
                    match.group(3) != null &&
                    !match.group(3).isEmpty
                ? new Padding(match.group(3))
                : null;
            return new CBCBlockCipherMac.fromCipherAndPadding(cipher, padding);
          });

  Uint8List _mac;

  Uint8List _buf;
  int _bufOff;
  final BlockCipher _cipher;
  final Padding _padding;

  final int _macSize;

  ParametersWithIV _params;

  /**
     * create a standard MAC based on a CBC block cipher. This will produce an
     * authentication code half the length of the block size of the cipher.
     *
     * @param cipher the cipher to be used as the basis of the MAC generation.
     */
  CBCBlockCipherMac.fromCipher(BlockCipher cipher)
      : this(cipher, (cipher.blockSize * 8) ~/ 2, null);

  /**
     * create a standard MAC based on a CBC block cipher. This will produce an
     * authentication code half the length of the block size of the cipher.
     *
     * @param cipher the cipher to be used as the basis of the MAC generation.
     * @param padding the padding to be used to complete the last block.
     */
  CBCBlockCipherMac.fromCipherAndPadding(BlockCipher cipher, Padding padding)
      : this(cipher, (cipher.blockSize * 8) ~/ 2, padding);

  /**
     * create a standard MAC based on a block cipher with the size of the
     * MAC been given in bits. This class uses CBC mode as the basis for the
     * MAC generation.
     * <p>
     * Note: the size of the MAC must be at least 24 bits (FIPS Publication 81),
     * or 16 bits if being used as a data authenticator (FIPS Publication 113),
     * and in general should be less than the size of the block cipher as it
     * reduces the chance of an exhaustive attack (see Handbook of Applied
     * Cryptography).
     *
     * @param cipher the cipher to be used as the basis of the MAC generation.
     * @param macSizeInBits the size of the MAC in bits, must be a multiple of 8.
     */
  CBCBlockCipherMac.fromCipherAndMacSize(BlockCipher cipher, int macSizeInBits)
      : this(cipher, macSizeInBits, null);

  /**
     * create a standard MAC based on a block cipher with the size of the
     * MAC been given in bits. This class uses CBC mode as the basis for the
     * MAC generation.
     * <p>
     * Note: the size of the MAC must be at least 24 bits (FIPS Publication 81),
     * or 16 bits if being used as a data authenticator (FIPS Publication 113),
     * and in general should be less than the size of the block cipher as it
     * reduces the chance of an exhaustive attack (see Handbook of Applied
     * Cryptography).
     *
     * @param cipher the cipher to be used as the basis of the MAC generation.
     * @param macSizeInBits the size of the MAC in bits, must be a multiple of 8.
     * @param padding the padding to be used to complete the last block.
     */
  CBCBlockCipherMac(BlockCipher cipher, int macSizeInBits, Padding padding)
      : _cipher = new CBCBlockCipher(cipher),
        _macSize = macSizeInBits ~/ 8,
        _padding = padding {
    if ((macSizeInBits % 8) != 0) {
      throw new ArgumentError("MAC size must be multiple of 8");
    }

    _mac = new Uint8List(cipher.blockSize);

    _buf = new Uint8List(cipher.blockSize);
    _bufOff = 0;
  }

  @override
  String get algorithmName {
    String paddingName = _padding != null ? "/${_padding.algorithmName}" : "";
    return "${_cipher.algorithmName}_CMAC${paddingName}";
  }

  @override
  void init(CipherParameters params) {
    if (params is ParametersWithIV) {
      this._params = params;
    } else if (params is KeyParameter) {
      final zeroIV = new Uint8List(params.key.length);
      this._params = new ParametersWithIV(params, zeroIV);
    }

    reset();

    _cipher.init(true, _params);
  }

  @override
  get macSize => _macSize;

  @override
  void updateByte(int inp) {
    if (_bufOff == _buf.length) {
      _cipher.processBlock(_buf, 0, _mac, 0);
      _bufOff = 0;
    }

    _buf[_bufOff++] = inp;
  }

  @override
  void update(Uint8List inp, int inOff, int len) {
    if (len < 0) {
      throw new ArgumentError("Can't have a negative input length!");
    }

    int blockSize = _cipher.blockSize;
    int gapLen = blockSize - _bufOff;

    if (len > gapLen) {
      _buf.setRange(_bufOff, _bufOff + gapLen, inp.sublist(inOff));

      _cipher.processBlock(_buf, 0, _mac, 0);

      _bufOff = 0;
      len -= gapLen;
      inOff += gapLen;

      while (len > blockSize) {
        _cipher.processBlock(inp, inOff, _mac, 0);

        len -= blockSize;
        inOff += blockSize;
      }
    }

    _buf.setRange(_bufOff, _bufOff + len, inp.sublist(inOff));

    _bufOff += len;
  }

  @override
  int doFinal(Uint8List out, int outOff) {
    int blockSize = _cipher.blockSize;

    if (_padding == null) {
      //
      // pad with zeroes
      //
      while (_bufOff < blockSize) {
        _buf[_bufOff] = 0;
        _bufOff++;
      }
    } else {
      if (_bufOff == blockSize) {
        _cipher.processBlock(_buf, 0, _mac, 0);
        _bufOff = 0;
      }

      _padding.addPadding(_buf, _bufOff);
    }

    _cipher.processBlock(_buf, 0, _mac, 0);

    out.setRange(outOff, outOff + _macSize, _mac);

    reset();

    return _macSize;
  }

  /// Reset the mac generator.
  @override
  void reset() {
    // clean the buffer.
    for (int i = 0; i < _buf.length; i++) {
      _buf[i] = 0;
    }

    _bufOff = 0;

    // reset the underlying cipher.
    _cipher.reset();

    if (_params != null) {
      _cipher.init(true, _params);
    }
  }
}
