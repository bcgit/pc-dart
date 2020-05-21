// See file LICENSE for more information.

library pointycastle.impl.digest.md4;

import "dart:typed_data";

import "package:pointycastle/api.dart";
import "package:pointycastle/src/impl/md4_family_digest.dart";
import "package:pointycastle/src/registry/registry.dart";
import "package:pointycastle/src/ufixnum.dart";

/// Implementation of MD4 digest
class MD4Digest extends MD4FamilyDigest implements Digest {
  static final FactoryConfig FACTORY_CONFIG =
      new StaticFactoryConfig(Digest, "MD4", () => MD4Digest());

  static const _DIGEST_LENGTH = 16;

  MD4Digest() : super(Endian.little, 4, 16);

  final algorithmName = "MD4";
  final digestSize = _DIGEST_LENGTH;

  void resetState() {
    state[0] = 0x67452301;
    state[1] = 0xefcdab89;
    state[2] = 0x98badcfe;
    state[3] = 0x10325476;
  }

  void processBlock() {
    var a = state[0];
    var b = state[1];
    var c = state[2];
    var d = state[3];

    // Round 1 - F cycle, 16 times.
    a = crotl32(a + _F(b, c, d) + buffer[0], _S11);
    d = crotl32(d + _F(a, b, c) + buffer[1], _S12);
    c = crotl32(c + _F(d, a, b) + buffer[2], _S13);
    b = crotl32(b + _F(c, d, a) + buffer[3], _S14);
    a = crotl32(a + _F(b, c, d) + buffer[4], _S11);
    d = crotl32(d + _F(a, b, c) + buffer[5], _S12);
    c = crotl32(c + _F(d, a, b) + buffer[6], _S13);
    b = crotl32(b + _F(c, d, a) + buffer[7], _S14);
    a = crotl32(a + _F(b, c, d) + buffer[8], _S11);
    d = crotl32(d + _F(a, b, c) + buffer[9], _S12);
    c = crotl32(c + _F(d, a, b) + buffer[10], _S13);
    b = crotl32(b + _F(c, d, a) + buffer[11], _S14);
    a = crotl32(a + _F(b, c, d) + buffer[12], _S11);
    d = crotl32(d + _F(a, b, c) + buffer[13], _S12);
    c = crotl32(c + _F(d, a, b) + buffer[14], _S13);
    b = crotl32(b + _F(c, d, a) + buffer[15], _S14);

    // Round 2 - G cycle, 16 times.
    a = crotl32(a + _G(b, c, d) + buffer[0] + 0x5a827999, _S21);
    d = crotl32(d + _G(a, b, c) + buffer[4] + 0x5a827999, _S22);
    c = crotl32(c + _G(d, a, b) + buffer[8] + 0x5a827999, _S23);
    b = crotl32(b + _G(c, d, a) + buffer[12] + 0x5a827999, _S24);
    a = crotl32(a + _G(b, c, d) + buffer[1] + 0x5a827999, _S21);
    d = crotl32(d + _G(a, b, c) + buffer[5] + 0x5a827999, _S22);
    c = crotl32(c + _G(d, a, b) + buffer[9] + 0x5a827999, _S23);
    b = crotl32(b + _G(c, d, a) + buffer[13] + 0x5a827999, _S24);
    a = crotl32(a + _G(b, c, d) + buffer[2] + 0x5a827999, _S21);
    d = crotl32(d + _G(a, b, c) + buffer[6] + 0x5a827999, _S22);
    c = crotl32(c + _G(d, a, b) + buffer[10] + 0x5a827999, _S23);
    b = crotl32(b + _G(c, d, a) + buffer[14] + 0x5a827999, _S24);
    a = crotl32(a + _G(b, c, d) + buffer[3] + 0x5a827999, _S21);
    d = crotl32(d + _G(a, b, c) + buffer[7] + 0x5a827999, _S22);
    c = crotl32(c + _G(d, a, b) + buffer[11] + 0x5a827999, _S23);
    b = crotl32(b + _G(c, d, a) + buffer[15] + 0x5a827999, _S24);

    // Round 3 - H cycle, 16 times.
    a = crotl32(a + _H(b, c, d) + buffer[0] + 0x6ed9eba1, _S31);
    d = crotl32(d + _H(a, b, c) + buffer[8] + 0x6ed9eba1, _S32);
    c = crotl32(c + _H(d, a, b) + buffer[4] + 0x6ed9eba1, _S33);
    b = crotl32(b + _H(c, d, a) + buffer[12] + 0x6ed9eba1, _S34);
    a = crotl32(a + _H(b, c, d) + buffer[2] + 0x6ed9eba1, _S31);
    d = crotl32(d + _H(a, b, c) + buffer[10] + 0x6ed9eba1, _S32);
    c = crotl32(c + _H(d, a, b) + buffer[6] + 0x6ed9eba1, _S33);
    b = crotl32(b + _H(c, d, a) + buffer[14] + 0x6ed9eba1, _S34);
    a = crotl32(a + _H(b, c, d) + buffer[1] + 0x6ed9eba1, _S31);
    d = crotl32(d + _H(a, b, c) + buffer[9] + 0x6ed9eba1, _S32);
    c = crotl32(c + _H(d, a, b) + buffer[5] + 0x6ed9eba1, _S33);
    b = crotl32(b + _H(c, d, a) + buffer[13] + 0x6ed9eba1, _S34);
    a = crotl32(a + _H(b, c, d) + buffer[3] + 0x6ed9eba1, _S31);
    d = crotl32(d + _H(a, b, c) + buffer[11] + 0x6ed9eba1, _S32);
    c = crotl32(c + _H(d, a, b) + buffer[7] + 0x6ed9eba1, _S33);
    b = crotl32(b + _H(c, d, a) + buffer[15] + 0x6ed9eba1, _S34);

    state[0] = clip32(state[0] + a);
    state[1] = clip32(state[1] + b);
    state[2] = clip32(state[2] + c);
    state[3] = clip32(state[3] + d);
  }

  // round 1 left rotates
  static const _S11 = 3;
  static const _S12 = 7;
  static const _S13 = 11;
  static const _S14 = 19;

  // round 2 left rotates
  static const _S21 = 3;
  static const _S22 = 5;
  static const _S23 = 9;
  static const _S24 = 13;

  // round 3 left rotates
  static const _S31 = 3;
  static const _S32 = 9;
  static const _S33 = 11;
  static const _S34 = 15;

  // F, G and H are the basic MD4 functions.
  int _F(int u, int v, int w) => (u & v) | (not32(u) & w);

  int _G(int u, int v, int w) => (u & v) | (u & w) | (v & w);

  int _H(int u, int v, int w) => u ^ v ^ w;
}
