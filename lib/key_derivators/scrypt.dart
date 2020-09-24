// See file LICENSE for more information.

library impl.key_derivator.scrypt;

import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/key_derivators/api.dart';
import 'package:pointycastle/key_derivators/pbkdf2.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/src/impl/base_key_derivator.dart';
import 'package:pointycastle/src/registry/registry.dart';
import 'package:pointycastle/src/ufixnum.dart';

///
/// Implementation of SCrypt password based key derivation function. See the next link for info on
/// how to choose N, r, and p:
/// * <http://stackoverflow.com/questions/11126315/what-are-optimal-scrypt-work-factors>
///
/// This implementation is based on Java implementation by Will Glozer, which can be found at:
/// * <https://github.com/wg/scrypt>
///
class Scrypt extends BaseKeyDerivator {
  static final FactoryConfig factoryConfig =
      StaticFactoryConfig(KeyDerivator, 'scrypt', () => Scrypt());

  static final int _maxValue = 0x7fffffff;

  ScryptParameters _params;

  @override
  final String algorithmName = 'scrypt';

  @override
  int get keySize => _params.desiredKeyLength;

  void reset() {
    _params = null;
  }

  @override
  void init(covariant ScryptParameters params) {
    _params = params;
  }

  @override
  int deriveKey(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    var key = _scryptJ(Uint8List.fromList(inp.sublist(inpOff)), _params.salt,
        _params.N, _params.r, _params.p, _params.desiredKeyLength);

    out.setRange(0, keySize, key);

    return keySize;
  }

  Uint8List _scryptJ(
      Uint8List passwd, Uint8List salt, int N, int r, int p, int dkLen) {
    if (N < 2 || (N & (N - 1)) != 0) {
      throw ArgumentError('N must be a power of 2 greater than 1');
    }

    if (N > _maxValue / 128 / r) {
      throw ArgumentError('Parameter N is too large');
    }

    if (r > _maxValue / 128 / p) {
      throw ArgumentError('Parameter r is too large');
    }

    final dk = Uint8List(dkLen);

    final b = Uint8List(128 * r * p);
    final xy = Uint8List(256 * r);
    final v = Uint8List(128 * r * N);

    final pbkdf2 = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64));

    pbkdf2.init(Pbkdf2Parameters(salt, 1, p * 128 * r));
    pbkdf2.deriveKey(passwd, 0, b, 0);

    for (var i = 0; i < p; i++) {
      _smix(b, i * 128 * r, r, N, v, xy);
    }

    pbkdf2.init(Pbkdf2Parameters(b, 1, dkLen));
    pbkdf2.deriveKey(passwd, 0, dk, 0);

    return dk;
  }

  void _smix(Uint8List B, int bi, int r, int N, Uint8List V, Uint8List xy) {
    var xi = 0;
    var yi = 128 * r;

    _arraycopy(B, bi, xy, xi, 128 * r);

    for (var i = 0; i < N; i++) {
      _arraycopy(xy, xi, V, i * (128 * r), 128 * r);
      _blockmixSalsa8(xy, xi, yi, r);
    }

    for (var i = 0; i < N; i++) {
      var j = _integerify(xy, xi, r) & (N - 1);
      _blockxor(V, j * (128 * r), xy, xi, 128 * r);
      _blockmixSalsa8(xy, xi, yi, r);
    }

    _arraycopy(xy, xi, B, bi, 128 * r);
  }

  void _blockmixSalsa8(Uint8List by, int bi, int yi, int r) {
    final X = Uint8List(64);

    _arraycopy(by, bi + (2 * r - 1) * 64, X, 0, 64);

    for (var i = 0; i < 2 * r; i++) {
      _blockxor(by, i * 64, X, 0, 64);
      _salsa20_8(X);
      _arraycopy(X, 0, by, yi + (i * 64), 64);
    }

    for (var i = 0; i < r; i++) {
      _arraycopy(by, yi + (i * 2) * 64, by, bi + (i * 64), 64);
    }

    for (var i = 0; i < r; i++) {
      _arraycopy(by, yi + (i * 2 + 1) * 64, by, bi + (i + r) * 64, 64);
    }
  }

  void _salsa20_8(Uint8List B) {
    final b32 = Uint32List(16);
    final x = Uint32List(16);

    for (var i = 0; i < 16; i++) {
      b32[i] = unpack32(B, i * 4, Endian.little);
    }

    _arraycopy(b32, 0, x, 0, 16);

    for (var i = 8; i > 0; i -= 2) {
      x[4] ^= crotl32(x[0] + x[12], 7);
      x[8] ^= crotl32(x[4] + x[0], 9);
      x[12] ^= crotl32(x[8] + x[4], 13);
      x[0] ^= crotl32(x[12] + x[8], 18);
      x[9] ^= crotl32(x[5] + x[1], 7);
      x[13] ^= crotl32(x[9] + x[5], 9);
      x[1] ^= crotl32(x[13] + x[9], 13);
      x[5] ^= crotl32(x[1] + x[13], 18);
      x[14] ^= crotl32(x[10] + x[6], 7);
      x[2] ^= crotl32(x[14] + x[10], 9);
      x[6] ^= crotl32(x[2] + x[14], 13);
      x[10] ^= crotl32(x[6] + x[2], 18);
      x[3] ^= crotl32(x[15] + x[11], 7);
      x[7] ^= crotl32(x[3] + x[15], 9);
      x[11] ^= crotl32(x[7] + x[3], 13);
      x[15] ^= crotl32(x[11] + x[7], 18);
      x[1] ^= crotl32(x[0] + x[3], 7);
      x[2] ^= crotl32(x[1] + x[0], 9);
      x[3] ^= crotl32(x[2] + x[1], 13);
      x[0] ^= crotl32(x[3] + x[2], 18);
      x[6] ^= crotl32(x[5] + x[4], 7);
      x[7] ^= crotl32(x[6] + x[5], 9);
      x[4] ^= crotl32(x[7] + x[6], 13);
      x[5] ^= crotl32(x[4] + x[7], 18);
      x[11] ^= crotl32(x[10] + x[9], 7);
      x[8] ^= crotl32(x[11] + x[10], 9);
      x[9] ^= crotl32(x[8] + x[11], 13);
      x[10] ^= crotl32(x[9] + x[8], 18);
      x[12] ^= crotl32(x[15] + x[14], 7);
      x[13] ^= crotl32(x[12] + x[15], 9);
      x[14] ^= crotl32(x[13] + x[12], 13);
      x[15] ^= crotl32(x[14] + x[13], 18);
    }

    for (var i = 0; i < 16; i++) {
      b32[i] = x[i] + b32[i];
    }

    for (var i = 0; i < 16; i++) {
      pack32(b32[i], B, i * 4, Endian.little);
    }
  }

  void _blockxor(Uint8List s, int si, Uint8List d, int di, int len) {
    for (var i = 0; i < len; i++) {
      d[di + i] ^= s[si + i];
    }
  }

  int _integerify(Uint8List b, int bi, int r) {
    bi += (2 * r - 1) * 64;
    return unpack32(b, bi, Endian.little);
  }

  void _arraycopy(
          List<int> inp, int inpOff, List<int> out, int outOff, int len) =>
      out.setRange(outOff, outOff + len, inp.sublist(inpOff));
}
