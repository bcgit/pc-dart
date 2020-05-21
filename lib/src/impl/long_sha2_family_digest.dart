// See file LICENSE for more information.

library pointycastle.src.impl.digests.long_sha2_family_digest;

import "dart:typed_data";

import "package:pointycastle/src/ufixnum.dart";
import "package:pointycastle/src/impl/base_digest.dart";

/// Base implementation of SHA-2 family algorithms SHA-384 and SHA-512.
abstract class LongSHA2FamilyDigest extends BaseDigest {
  static const _BYTE_LENGTH = 128;

  static final _MAX_BYTE_COUNT1 = new Register64(0x1fffffff, 0xffffffff);

  final H1 = new Register64();
  final H2 = new Register64();
  final H3 = new Register64();
  final H4 = new Register64();
  final H5 = new Register64();
  final H6 = new Register64();
  final H7 = new Register64();
  final H8 = new Register64();

  final _wordBuffer = new Uint8List(8);
  int _wordBufferOffset = 0;

  final _W = new Register64List(80);
  int _wOff = 0;

  final _byteCount1 = new Register64(); // TODO: convert to list
  final _byteCount2 = new Register64();

  LongSHA2FamilyDigest() {
    reset();
  }

  int get byteLength => _BYTE_LENGTH;

  void reset() {
    _byteCount1.set(0);
    _byteCount2.set(0);

    _wordBufferOffset = 0;
    _wordBuffer.fillRange(0, _wordBuffer.length, 0);

    _wOff = 0;
    _W.fillRange(0, _W.length, 0);
  }

  void updateByte(int inp) {
    _wordBuffer[_wordBufferOffset++] = inp;

    if (_wordBufferOffset == _wordBuffer.length) {
      _processWord(_wordBuffer, 0);
      _wordBufferOffset = 0;
    }

    _byteCount1.sum(1);
  }

  void update(Uint8List inp, int inpOff, int len) {
    // fill the current word
    while ((_wordBufferOffset != 0) && (len > 0)) {
      updateByte(inp[inpOff]);

      inpOff++;
      len--;
    }

    // process whole words.
    while (len > _wordBuffer.length) {
      _processWord(inp, inpOff);

      inpOff += _wordBuffer.length;
      len -= _wordBuffer.length;
      _byteCount1.sum(_wordBuffer.length);
    }

    // load in the remainder.
    while (len > 0) {
      updateByte(inp[inpOff]);

      inpOff++;
      len--;
    }
  }

  void finish() {
    _adjustByteCounts();

    var lowBitLength = new Register64(_byteCount1)..shiftl(3);
    var hiBitLength = _byteCount2;

    // add the pad bytes.
    updateByte(128);

    while (_wordBufferOffset != 0) {
      updateByte(0);
    }

    _processLength(lowBitLength, hiBitLength);

    _processBlock();
  }

  void _processWord(Uint8List inp, int inpOff) {
    _W[_wOff++].unpack(inp, inpOff, Endian.big);

    if (_wOff == 16) {
      _processBlock();
    }
  }

  /**
   * Adjust the byte counts so that byteCount2 represents the upper long (less 3 bits) word of the
   * byte count.
   */
  void _adjustByteCounts() {
    if (_byteCount1 > _MAX_BYTE_COUNT1) {
      _byteCount2.sum(new Register64(_byteCount1)..shiftr(61));
      _byteCount1.and(_MAX_BYTE_COUNT1);
    }
  }

  void _processLength(Register64 lowW, Register64 hiW) {
    if (_wOff > 14) {
      _processBlock();
    }

    _W[14].set(hiW);
    _W[15].set(lowW);
  }

  void _processBlock() {
    _adjustByteCounts();

    // expand 16 word block into 80 word blocks.
    for (var t = 16; t < 80; t++) {
      // _W[t] = _Sigma1(_W[t - 2]) + _W[t - 7] + _Sigma0(_W[t - 15]) + _W[t - 16];
      _W[t].set(_Sigma1(_W[t - 2])
        ..sum(_W[t - 7])
        ..sum(_Sigma0(_W[t - 15]))
        ..sum(_W[t - 16]));
    }

    var a = new Register64(H1);
    var b = new Register64(H2);
    var c = new Register64(H3);
    var d = new Register64(H4);
    var e = new Register64(H5);
    var f = new Register64(H6);
    var g = new Register64(H7);
    var h = new Register64(H8);

    var t = 0;
    for (var i = 0; i < 10; i++) {
      // t = 8 * i
      h..sum(_Sum1(e))..sum(_Ch(e, f, g))..sum(_K[t])..sum(_W[t++]);
      d.sum(h);
      h..sum(_Sum0(a))..sum(_Maj(a, b, c));

      // t = 8 * i + 1
      g..sum(_Sum1(d))..sum(_Ch(d, e, f))..sum(_K[t])..sum(_W[t++]);
      c.sum(g);
      g..sum(_Sum0(h))..sum(_Maj(h, a, b));

      // t = 8 * i + 2
      f..sum(_Sum1(c))..sum(_Ch(c, d, e))..sum(_K[t])..sum(_W[t++]);
      b.sum(f);
      f..sum(_Sum0(g))..sum(_Maj(g, h, a));

      // t = 8 * i + 3
      e..sum(_Sum1(b))..sum(_Ch(b, c, d))..sum(_K[t])..sum(_W[t++]);
      a.sum(e);
      e..sum(_Sum0(f))..sum(_Maj(f, g, h));

      // t = 8 * i + 4
      d..sum(_Sum1(a))..sum(_Ch(a, b, c))..sum(_K[t])..sum(_W[t++]);
      h.sum(d);
      d..sum(_Sum0(e))..sum(_Maj(e, f, g));

      // t = 8 * i + 5
      c..sum(_Sum1(h))..sum(_Ch(h, a, b))..sum(_K[t])..sum(_W[t++]);
      g.sum(c);
      c..sum(_Sum0(d))..sum(_Maj(d, e, f));

      // t = 8 * i + 6
      b..sum(_Sum1(g))..sum(_Ch(g, h, a))..sum(_K[t])..sum(_W[t++]);
      f.sum(b);
      b..sum(_Sum0(c))..sum(_Maj(c, d, e));

      // t = 8 * i + 7
      a..sum(_Sum1(f))..sum(_Ch(f, g, h))..sum(_K[t])..sum(_W[t++]);
      e.sum(a);
      a..sum(_Sum0(b))..sum(_Maj(b, c, d));
    }

    H1.sum(a);
    H2.sum(b);
    H3.sum(c);
    H4.sum(d);
    H5.sum(e);
    H6.sum(f);
    H7.sum(g);
    H8.sum(h);

    // reset the offset and clean out the word buffer.
    _wOff = 0;
    _W.fillRange(0, 16, 0);
  }

  Register64 _Ch(Register64 x, Register64 y, Register64 z) {
    // r += ((x & y) ^ ((~x) & z));
    Register64 r0 = new Register64(x);
    r0.and(y);

    Register64 r1 = new Register64(x);
    r1.not();
    r1.and(z);

    r0.xor(r1);
    return r0;
  }

  Register64 _Maj(Register64 x, Register64 y, Register64 z) {
    // r += ((x & y) ^ (x & z) ^ (y & z));
    Register64 r0 = new Register64(x);
    r0.and(y);

    Register64 r1 = new Register64(x);
    r1.and(z);

    Register64 r2 = new Register64(y);
    r2.and(z);

    r0.xor(r1);
    r0.xor(r2);

    return r0;
  }

  Register64 _Sum0(Register64 x) {
    // r += ((x << 36)|(x >> 28)) ^ ((x << 30)|(x >> 34)) ^ ((x << 25)|(x >> 39));
    Register64 r0 = new Register64(x);
    r0.rotl(36);

    Register64 r1 = new Register64(x);
    r1.rotl(30);

    Register64 r2 = new Register64(x);
    r2.rotl(25);

    r0.xor(r1);
    r0.xor(r2);

    return r0;
  }

  Register64 _Sum1(Register64 x) {
    // r += ((x << 50)|(x >> 14)) ^ ((x << 46)|(x >> 18)) ^ ((x << 23)|(x >> 41));
    Register64 r0 = new Register64(x);
    r0.rotl(50);

    Register64 r1 = new Register64(x);
    r1.rotl(46);

    Register64 r2 = new Register64(x);
    r2.rotl(23);

    r0.xor(r1);
    r0.xor(r2);

    return r0;
  }

  Register64 _Sigma0(Register64 x) {
    // r = (((x << 63)|(x >> 1)) ^ ((x << 56)|(x >> 8)) ^ (x >> 7));
    Register64 r0 = new Register64(x);
    r0.rotl(63);

    Register64 r1 = new Register64(x);
    r1.rotl(56);

    Register64 r2 = new Register64(x);
    r2.shiftr(7);

    r0.xor(r1);
    r0.xor(r2);

    return r0;
  }

  Register64 _Sigma1(Register64 x) {
    // r = (((x << 45)|(x >> 19)) ^ ((x << 3)|(x >> 61)) ^ (x >> 6));
    Register64 r0 = new Register64(x);
    r0.rotl(45);

    Register64 r1 = new Register64(x);
    r1.rotl(3);

    Register64 r2 = new Register64(x);
    r2.shiftr(6);

    r0.xor(r1);
    r0.xor(r2);

    return r0;
  }

  /**
   * SHA-384 and SHA-512 constants: represent the first 64 bits of the fractional parts of the cube
   * roots of the first sixty-four prime numbers)
   */
  static final _K = <Register64>[
    new Register64(0x428a2f98, 0xd728ae22),
    new Register64(0x71374491, 0x23ef65cd),
    new Register64(0xb5c0fbcf, 0xec4d3b2f),
    new Register64(0xe9b5dba5, 0x8189dbbc),
    new Register64(0x3956c25b, 0xf348b538),
    new Register64(0x59f111f1, 0xb605d019),
    new Register64(0x923f82a4, 0xaf194f9b),
    new Register64(0xab1c5ed5, 0xda6d8118),
    new Register64(0xd807aa98, 0xa3030242),
    new Register64(0x12835b01, 0x45706fbe),
    new Register64(0x243185be, 0x4ee4b28c),
    new Register64(0x550c7dc3, 0xd5ffb4e2),
    new Register64(0x72be5d74, 0xf27b896f),
    new Register64(0x80deb1fe, 0x3b1696b1),
    new Register64(0x9bdc06a7, 0x25c71235),
    new Register64(0xc19bf174, 0xcf692694),
    new Register64(0xe49b69c1, 0x9ef14ad2),
    new Register64(0xefbe4786, 0x384f25e3),
    new Register64(0x0fc19dc6, 0x8b8cd5b5),
    new Register64(0x240ca1cc, 0x77ac9c65),
    new Register64(0x2de92c6f, 0x592b0275),
    new Register64(0x4a7484aa, 0x6ea6e483),
    new Register64(0x5cb0a9dc, 0xbd41fbd4),
    new Register64(0x76f988da, 0x831153b5),
    new Register64(0x983e5152, 0xee66dfab),
    new Register64(0xa831c66d, 0x2db43210),
    new Register64(0xb00327c8, 0x98fb213f),
    new Register64(0xbf597fc7, 0xbeef0ee4),
    new Register64(0xc6e00bf3, 0x3da88fc2),
    new Register64(0xd5a79147, 0x930aa725),
    new Register64(0x06ca6351, 0xe003826f),
    new Register64(0x14292967, 0x0a0e6e70),
    new Register64(0x27b70a85, 0x46d22ffc),
    new Register64(0x2e1b2138, 0x5c26c926),
    new Register64(0x4d2c6dfc, 0x5ac42aed),
    new Register64(0x53380d13, 0x9d95b3df),
    new Register64(0x650a7354, 0x8baf63de),
    new Register64(0x766a0abb, 0x3c77b2a8),
    new Register64(0x81c2c92e, 0x47edaee6),
    new Register64(0x92722c85, 0x1482353b),
    new Register64(0xa2bfe8a1, 0x4cf10364),
    new Register64(0xa81a664b, 0xbc423001),
    new Register64(0xc24b8b70, 0xd0f89791),
    new Register64(0xc76c51a3, 0x0654be30),
    new Register64(0xd192e819, 0xd6ef5218),
    new Register64(0xd6990624, 0x5565a910),
    new Register64(0xf40e3585, 0x5771202a),
    new Register64(0x106aa070, 0x32bbd1b8),
    new Register64(0x19a4c116, 0xb8d2d0c8),
    new Register64(0x1e376c08, 0x5141ab53),
    new Register64(0x2748774c, 0xdf8eeb99),
    new Register64(0x34b0bcb5, 0xe19b48a8),
    new Register64(0x391c0cb3, 0xc5c95a63),
    new Register64(0x4ed8aa4a, 0xe3418acb),
    new Register64(0x5b9cca4f, 0x7763e373),
    new Register64(0x682e6ff3, 0xd6b2b8a3),
    new Register64(0x748f82ee, 0x5defb2fc),
    new Register64(0x78a5636f, 0x43172f60),
    new Register64(0x84c87814, 0xa1f0ab72),
    new Register64(0x8cc70208, 0x1a6439ec),
    new Register64(0x90befffa, 0x23631e28),
    new Register64(0xa4506ceb, 0xde82bde9),
    new Register64(0xbef9a3f7, 0xb2c67915),
    new Register64(0xc67178f2, 0xe372532b),
    new Register64(0xca273ece, 0xea26619c),
    new Register64(0xd186b8c7, 0x21c0c207),
    new Register64(0xeada7dd6, 0xcde0eb1e),
    new Register64(0xf57d4f7f, 0xee6ed178),
    new Register64(0x06f067aa, 0x72176fba),
    new Register64(0x0a637dc5, 0xa2c898a6),
    new Register64(0x113f9804, 0xbef90dae),
    new Register64(0x1b710b35, 0x131c471b),
    new Register64(0x28db77f5, 0x23047d84),
    new Register64(0x32caab7b, 0x40c72493),
    new Register64(0x3c9ebe0a, 0x15c9bebc),
    new Register64(0x431d67c4, 0x9c100d4c),
    new Register64(0x4cc5d4be, 0xcb3e42b6),
    new Register64(0x597f299c, 0xfc657e2a),
    new Register64(0x5fcb6fab, 0x3ad6faec),
    new Register64(0x6c44198c, 0x4a475817)
  ];
}
