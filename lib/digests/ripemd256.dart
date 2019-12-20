// See file LICENSE for more information.

library pointycastle.impl.digest.ripemd256;

import "dart:typed_data";

import "package:pointycastle/api.dart";
import "package:pointycastle/src/impl/md4_family_digest.dart";
import "package:pointycastle/src/registry/registry.dart";
import "package:pointycastle/src/ufixnum.dart";

/// Implementation of RIPEMD-256 digest.
class RIPEMD256Digest extends MD4FamilyDigest implements Digest {
  static final FactoryConfig FACTORY_CONFIG =
      new StaticFactoryConfig(Digest, "RIPEMD-256", () => RIPEMD256Digest());

  static const _DIGEST_LENGTH = 32;

  RIPEMD256Digest() : super(Endian.little, 8, 16);

  final algorithmName = "RIPEMD-256";
  final digestSize = _DIGEST_LENGTH;

  void resetState() {
    state[0] = 0x67452301;
    state[1] = 0xefcdab89;
    state[2] = 0x98badcfe;
    state[3] = 0x10325476;
    state[4] = 0x76543210;
    state[5] = 0xFEDCBA98;
    state[6] = 0x89ABCDEF;
    state[7] = 0x01234567;
  }

  void processBlock() {
    var a, aa;
    var b, bb;
    var c, cc;
    var d, dd;
    var t;

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    aa = state[4];
    bb = state[5];
    cc = state[6];
    dd = state[7];

    // Round 1
    a = _F1(a, b, c, d, buffer[0], 11);
    d = _F1(d, a, b, c, buffer[1], 14);
    c = _F1(c, d, a, b, buffer[2], 15);
    b = _F1(b, c, d, a, buffer[3], 12);
    a = _F1(a, b, c, d, buffer[4], 5);
    d = _F1(d, a, b, c, buffer[5], 8);
    c = _F1(c, d, a, b, buffer[6], 7);
    b = _F1(b, c, d, a, buffer[7], 9);
    a = _F1(a, b, c, d, buffer[8], 11);
    d = _F1(d, a, b, c, buffer[9], 13);
    c = _F1(c, d, a, b, buffer[10], 14);
    b = _F1(b, c, d, a, buffer[11], 15);
    a = _F1(a, b, c, d, buffer[12], 6);
    d = _F1(d, a, b, c, buffer[13], 7);
    c = _F1(c, d, a, b, buffer[14], 9);
    b = _F1(b, c, d, a, buffer[15], 8);

    aa = _FF4(aa, bb, cc, dd, buffer[5], 8);
    dd = _FF4(dd, aa, bb, cc, buffer[14], 9);
    cc = _FF4(cc, dd, aa, bb, buffer[7], 9);
    bb = _FF4(bb, cc, dd, aa, buffer[0], 11);
    aa = _FF4(aa, bb, cc, dd, buffer[9], 13);
    dd = _FF4(dd, aa, bb, cc, buffer[2], 15);
    cc = _FF4(cc, dd, aa, bb, buffer[11], 15);
    bb = _FF4(bb, cc, dd, aa, buffer[4], 5);
    aa = _FF4(aa, bb, cc, dd, buffer[13], 7);
    dd = _FF4(dd, aa, bb, cc, buffer[6], 7);
    cc = _FF4(cc, dd, aa, bb, buffer[15], 8);
    bb = _FF4(bb, cc, dd, aa, buffer[8], 11);
    aa = _FF4(aa, bb, cc, dd, buffer[1], 14);
    dd = _FF4(dd, aa, bb, cc, buffer[10], 14);
    cc = _FF4(cc, dd, aa, bb, buffer[3], 12);
    bb = _FF4(bb, cc, dd, aa, buffer[12], 6);

    t = a;
    a = aa;
    aa = t;

    // Round 2
    a = _F2(a, b, c, d, buffer[7], 7);
    d = _F2(d, a, b, c, buffer[4], 6);
    c = _F2(c, d, a, b, buffer[13], 8);
    b = _F2(b, c, d, a, buffer[1], 13);
    a = _F2(a, b, c, d, buffer[10], 11);
    d = _F2(d, a, b, c, buffer[6], 9);
    c = _F2(c, d, a, b, buffer[15], 7);
    b = _F2(b, c, d, a, buffer[3], 15);
    a = _F2(a, b, c, d, buffer[12], 7);
    d = _F2(d, a, b, c, buffer[0], 12);
    c = _F2(c, d, a, b, buffer[9], 15);
    b = _F2(b, c, d, a, buffer[5], 9);
    a = _F2(a, b, c, d, buffer[2], 11);
    d = _F2(d, a, b, c, buffer[14], 7);
    c = _F2(c, d, a, b, buffer[11], 13);
    b = _F2(b, c, d, a, buffer[8], 12);

    aa = _FF3(aa, bb, cc, dd, buffer[6], 9);
    dd = _FF3(dd, aa, bb, cc, buffer[11], 13);
    cc = _FF3(cc, dd, aa, bb, buffer[3], 15);
    bb = _FF3(bb, cc, dd, aa, buffer[7], 7);
    aa = _FF3(aa, bb, cc, dd, buffer[0], 12);
    dd = _FF3(dd, aa, bb, cc, buffer[13], 8);
    cc = _FF3(cc, dd, aa, bb, buffer[5], 9);
    bb = _FF3(bb, cc, dd, aa, buffer[10], 11);
    aa = _FF3(aa, bb, cc, dd, buffer[14], 7);
    dd = _FF3(dd, aa, bb, cc, buffer[15], 7);
    cc = _FF3(cc, dd, aa, bb, buffer[8], 12);
    bb = _FF3(bb, cc, dd, aa, buffer[12], 7);
    aa = _FF3(aa, bb, cc, dd, buffer[4], 6);
    dd = _FF3(dd, aa, bb, cc, buffer[9], 15);
    cc = _FF3(cc, dd, aa, bb, buffer[1], 13);
    bb = _FF3(bb, cc, dd, aa, buffer[2], 11);

    t = b;
    b = bb;
    bb = t;

    // Round 3
    a = _F3(a, b, c, d, buffer[3], 11);
    d = _F3(d, a, b, c, buffer[10], 13);
    c = _F3(c, d, a, b, buffer[14], 6);
    b = _F3(b, c, d, a, buffer[4], 7);
    a = _F3(a, b, c, d, buffer[9], 14);
    d = _F3(d, a, b, c, buffer[15], 9);
    c = _F3(c, d, a, b, buffer[8], 13);
    b = _F3(b, c, d, a, buffer[1], 15);
    a = _F3(a, b, c, d, buffer[2], 14);
    d = _F3(d, a, b, c, buffer[7], 8);
    c = _F3(c, d, a, b, buffer[0], 13);
    b = _F3(b, c, d, a, buffer[6], 6);
    a = _F3(a, b, c, d, buffer[13], 5);
    d = _F3(d, a, b, c, buffer[11], 12);
    c = _F3(c, d, a, b, buffer[5], 7);
    b = _F3(b, c, d, a, buffer[12], 5);

    aa = _FF2(aa, bb, cc, dd, buffer[15], 9);
    dd = _FF2(dd, aa, bb, cc, buffer[5], 7);
    cc = _FF2(cc, dd, aa, bb, buffer[1], 15);
    bb = _FF2(bb, cc, dd, aa, buffer[3], 11);
    aa = _FF2(aa, bb, cc, dd, buffer[7], 8);
    dd = _FF2(dd, aa, bb, cc, buffer[14], 6);
    cc = _FF2(cc, dd, aa, bb, buffer[6], 6);
    bb = _FF2(bb, cc, dd, aa, buffer[9], 14);
    aa = _FF2(aa, bb, cc, dd, buffer[11], 12);
    dd = _FF2(dd, aa, bb, cc, buffer[8], 13);
    cc = _FF2(cc, dd, aa, bb, buffer[12], 5);
    bb = _FF2(bb, cc, dd, aa, buffer[2], 14);
    aa = _FF2(aa, bb, cc, dd, buffer[10], 13);
    dd = _FF2(dd, aa, bb, cc, buffer[0], 13);
    cc = _FF2(cc, dd, aa, bb, buffer[4], 7);
    bb = _FF2(bb, cc, dd, aa, buffer[13], 5);

    t = c;
    c = cc;
    cc = t;

    // Round 4
    a = _F4(a, b, c, d, buffer[1], 11);
    d = _F4(d, a, b, c, buffer[9], 12);
    c = _F4(c, d, a, b, buffer[11], 14);
    b = _F4(b, c, d, a, buffer[10], 15);
    a = _F4(a, b, c, d, buffer[0], 14);
    d = _F4(d, a, b, c, buffer[8], 15);
    c = _F4(c, d, a, b, buffer[12], 9);
    b = _F4(b, c, d, a, buffer[4], 8);
    a = _F4(a, b, c, d, buffer[13], 9);
    d = _F4(d, a, b, c, buffer[3], 14);
    c = _F4(c, d, a, b, buffer[7], 5);
    b = _F4(b, c, d, a, buffer[15], 6);
    a = _F4(a, b, c, d, buffer[14], 8);
    d = _F4(d, a, b, c, buffer[5], 6);
    c = _F4(c, d, a, b, buffer[6], 5);
    b = _F4(b, c, d, a, buffer[2], 12);

    aa = _FF1(aa, bb, cc, dd, buffer[8], 15);
    dd = _FF1(dd, aa, bb, cc, buffer[6], 5);
    cc = _FF1(cc, dd, aa, bb, buffer[4], 8);
    bb = _FF1(bb, cc, dd, aa, buffer[1], 11);
    aa = _FF1(aa, bb, cc, dd, buffer[3], 14);
    dd = _FF1(dd, aa, bb, cc, buffer[11], 14);
    cc = _FF1(cc, dd, aa, bb, buffer[15], 6);
    bb = _FF1(bb, cc, dd, aa, buffer[0], 14);
    aa = _FF1(aa, bb, cc, dd, buffer[5], 6);
    dd = _FF1(dd, aa, bb, cc, buffer[12], 9);
    cc = _FF1(cc, dd, aa, bb, buffer[2], 12);
    bb = _FF1(bb, cc, dd, aa, buffer[13], 9);
    aa = _FF1(aa, bb, cc, dd, buffer[9], 12);
    dd = _FF1(dd, aa, bb, cc, buffer[7], 5);
    cc = _FF1(cc, dd, aa, bb, buffer[10], 15);
    bb = _FF1(bb, cc, dd, aa, buffer[14], 8);

    t = d;
    d = dd;
    dd = t;

    state[0] = sum32(state[0], a);
    state[1] = sum32(state[1], b);
    state[2] = sum32(state[2], c);
    state[3] = sum32(state[3], d);
    state[4] = sum32(state[4], aa);
    state[5] = sum32(state[5], bb);
    state[6] = sum32(state[6], cc);
    state[7] = sum32(state[7], dd);
  }

  int _f1(int x, int y, int z) => x ^ y ^ z;

  int _f2(int x, int y, int z) => (x & y) | (~x & z);

  int _f3(int x, int y, int z) => (x | ~y) ^ z;

  int _f4(int x, int y, int z) => (x & z) | (y & ~z);

  int _F1(int a, int b, int c, int d, int x, int s) =>
      crotl32(a + _f1(b, c, d) + x, s);

  int _F2(int a, int b, int c, int d, int x, int s) =>
      crotl32(a + _f2(b, c, d) + x + 0x5a827999, s);

  int _F3(int a, int b, int c, int d, int x, int s) =>
      crotl32(a + _f3(b, c, d) + x + 0x6ed9eba1, s);

  int _F4(int a, int b, int c, int d, int x, int s) =>
      crotl32(a + _f4(b, c, d) + x + 0x8f1bbcdc, s);

  int _FF1(int a, int b, int c, int d, int x, int s) =>
      crotl32(a + _f1(b, c, d) + x, s);

  int _FF2(int a, int b, int c, int d, int x, int s) =>
      crotl32(a + _f2(b, c, d) + x + 0x6d703ef3, s);

  int _FF3(int a, int b, int c, int d, int x, int s) =>
      crotl32(a + _f3(b, c, d) + x + 0x5c4dd124, s);

  int _FF4(int a, int b, int c, int d, int x, int s) =>
      crotl32(a + _f4(b, c, d) + x + 0x50a28be6, s);
}
