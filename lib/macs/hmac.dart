// See file LICENSE for more information.

library pointycastle.impl.mac.hmac;

import "dart:typed_data";

import "package:pointycastle/api.dart";
import "package:pointycastle/src/registry/registry.dart";
import "package:pointycastle/src/impl/base_mac.dart";

/**
 * HMAC implementation based on RFC2104
 *
 * H(K XOR opad, H(K XOR ipad, text))
 */
class HMac extends BaseMac {
  static final FactoryConfig FACTORY_CONFIG =
      new DynamicFactoryConfig.suffix(Mac, "/HMAC", (_, Match match) {
    final String digestName = match.group(1);
    final int blockLength = _DIGEST_BLOCK_LENGTH[digestName];
    if (blockLength == null) {
      throw new RegistryFactoryException("Digest $digestName unknown for "
          "HMAC construction.");
    }
    return () {
      Digest digest = new Digest(digestName);
      return new HMac(digest, blockLength);
    };
  });

  //TODO make this more generic
  static final Map<String, int> _DIGEST_BLOCK_LENGTH = {
    "GOST3411": 32,
    "MD2": 16,
    "MD4": 64,
    "MD5": 64,
    "RIPEMD-128": 64,
    "RIPEMD-160": 64,
    "SHA-1": 64,
    "SHA-224": 64,
    "SHA-256": 64,
    "SHA-384": 128,
    "SHA-512": 128,
    "Tiger": 64,
    "Whirlpool": 64,
  };

  //TODO reindent

  static final _IPAD = 0x36;
  static final _OPAD = 0x5C;

  Digest _digest;
  int _digestSize;
  int _blockLength;

  Uint8List _inputPad;
  Uint8List _outputBuf;

  HMac(this._digest, this._blockLength) {
    _digestSize = _digest.digestSize;
    _inputPad = new Uint8List(_blockLength);
    _outputBuf = new Uint8List(_blockLength + _digestSize);
  }

  String get algorithmName => "${_digest.algorithmName}/HMAC";

  int get macSize => _digestSize;

  void reset() {
    // reset the underlying digest.
    _digest.reset();

    // reinitialize the digest.
    _digest.update(_inputPad, 0, _inputPad.length);
  }

  void init(covariant KeyParameter params) {
    _digest.reset();

    var key = params.key;
    var keyLength = key.length;

    if (keyLength > _blockLength) {
      _digest.update(key, 0, keyLength);
      _digest.doFinal(_inputPad, 0);

      keyLength = _digestSize;
    } else {
      _inputPad.setRange(0, keyLength, key);
    }

    _inputPad.fillRange(keyLength, _inputPad.length, 0);

    _outputBuf.setRange(0, _blockLength, _inputPad);

    _xorPad(_inputPad, _blockLength, _IPAD);
    _xorPad(_outputBuf, _blockLength, _OPAD);

    _digest.update(_inputPad, 0, _inputPad.length);
  }

  void updateByte(int inp) {
    _digest.updateByte(inp);
  }

  void update(Uint8List inp, int inpOff, int len) {
    _digest.update(inp, inpOff, len);
  }

  int doFinal(Uint8List out, int outOff) {
    _digest.doFinal(_outputBuf, _blockLength);
    _digest.update(_outputBuf, 0, _outputBuf.length);

    var len = _digest.doFinal(out, outOff);
    _outputBuf.fillRange(_blockLength, _outputBuf.length, 0);
    _digest.update(_inputPad, 0, _inputPad.length);

    return len;
  }

  void _xorPad(Uint8List pad, int len, int n) {
    for (var i = 0; i < len; i++) {
      pad[i] ^= n;
    }
  }
}
