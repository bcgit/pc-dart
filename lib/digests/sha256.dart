// See file LICENSE for more information.

library pointycastle.impl.digest.sha256;

import "dart:typed_data";

import "package:pointycastle/api.dart";
import "package:pointycastle/src/impl/md4_family_digest.dart";
import "package:pointycastle/src/registry/registry.dart";
import "package:pointycastle/src/ufixnum.dart";

/// Implementation of SHA-256 digest.
class SHA256Digest extends MD4FamilyDigest implements Digest {
  static final FactoryConfig FACTORY_CONFIG =
      new StaticFactoryConfig(Digest, "SHA-256", () => SHA256Digest());

  static const _DIGEST_LENGTH = 32;

  SHA256Digest() : super(Endian.big, 8, 64);

  final algorithmName = "SHA-256";
  final digestSize = _DIGEST_LENGTH;

  void resetState() {
    state[0] = 0x6a09e667;
    state[1] = 0xbb67ae85;
    state[2] = 0x3c6ef372;
    state[3] = 0xa54ff53a;
    state[4] = 0x510e527f;
    state[5] = 0x9b05688c;
    state[6] = 0x1f83d9ab;
    state[7] = 0x5be0cd19;
  }

  void processBlock() {
    // expand 16 word block into 64 word blocks.
    for (var t = 16; t < 64; t++) {
      buffer[t] = clip32(_Theta1(buffer[t - 2]) +
          buffer[t - 7] +
          _Theta0(buffer[t - 15]) +
          buffer[t - 16]);
    }

    // set up working variables.
    var a = state[0];
    var b = state[1];
    var c = state[2];
    var d = state[3];
    var e = state[4];
    var f = state[5];
    var g = state[6];
    var h = state[7];

    var t = 0;

    for (var i = 0; i < 8; i++) {
      // t = 8 * i
      h = clip32(h + _Sum1(e) + _Ch(e, f, g) + _K[t] + buffer[t]);
      d = clip32(d + h);
      h = clip32(h + _Sum0(a) + _Maj(a, b, c));
      ++t;

      // t = 8 * i + 1
      g = clip32(g + _Sum1(d) + _Ch(d, e, f) + _K[t] + buffer[t]);
      c = clip32(c + g);
      g = clip32(g + _Sum0(h) + _Maj(h, a, b));
      ++t;

      // t = 8 * i + 2
      f = clip32(f + _Sum1(c) + _Ch(c, d, e) + _K[t] + buffer[t]);
      b = clip32(b + f);
      f = clip32(f + _Sum0(g) + _Maj(g, h, a));
      ++t;

      // t = 8 * i + 3
      e = clip32(e + _Sum1(b) + _Ch(b, c, d) + _K[t] + buffer[t]);
      a = clip32(a + e);
      e = clip32(e + _Sum0(f) + _Maj(f, g, h));
      ++t;

      // t = 8 * i + 4
      d = clip32(d + _Sum1(a) + _Ch(a, b, c) + _K[t] + buffer[t]);
      h = clip32(h + d);
      d = clip32(d + _Sum0(e) + _Maj(e, f, g));
      ++t;

      // t = 8 * i + 5
      c = clip32(c + _Sum1(h) + _Ch(h, a, b) + _K[t] + buffer[t]);
      g = clip32(g + c);
      c = clip32(c + _Sum0(d) + _Maj(d, e, f));
      ++t;

      // t = 8 * i + 6
      b = clip32(b + _Sum1(g) + _Ch(g, h, a) + _K[t] + buffer[t]);
      f = clip32(f + b);
      b = clip32(b + _Sum0(c) + _Maj(c, d, e));
      ++t;

      // t = 8 * i + 7
      a = clip32(a + _Sum1(f) + _Ch(f, g, h) + _K[t] + buffer[t]);
      e = clip32(e + a);
      a = clip32(a + _Sum0(b) + _Maj(b, c, d));
      ++t;
    }

    state[0] = clip32(state[0] + a);
    state[1] = clip32(state[1] + b);
    state[2] = clip32(state[2] + c);
    state[3] = clip32(state[3] + d);
    state[4] = clip32(state[4] + e);
    state[5] = clip32(state[5] + f);
    state[6] = clip32(state[6] + g);
    state[7] = clip32(state[7] + h);
  }

  int _Ch(int x, int y, int z) => (x & y) ^ ((~x) & z);

  int _Maj(int x, int y, int z) => (x & y) ^ (x & z) ^ (y & z);

  int _Sum0(int x) => rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);

  int _Sum1(int x) => rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);

  int _Theta0(int x) => rotr32(x, 7) ^ rotr32(x, 18) ^ shiftr32(x, 3);

  int _Theta1(int x) => rotr32(x, 17) ^ rotr32(x, 19) ^ shiftr32(x, 10);

  /**
   * SHA-256 Constants (represent the first 32 bits of the fractional parts of the cube roots of the
   * first sixty-four prime numbers)
   */
  static final _K = [
    0x428a2f98,
    0x71374491,
    0xb5c0fbcf,
    0xe9b5dba5,
    0x3956c25b,
    0x59f111f1,
    0x923f82a4,
    0xab1c5ed5,
    0xd807aa98,
    0x12835b01,
    0x243185be,
    0x550c7dc3,
    0x72be5d74,
    0x80deb1fe,
    0x9bdc06a7,
    0xc19bf174,
    0xe49b69c1,
    0xefbe4786,
    0x0fc19dc6,
    0x240ca1cc,
    0x2de92c6f,
    0x4a7484aa,
    0x5cb0a9dc,
    0x76f988da,
    0x983e5152,
    0xa831c66d,
    0xb00327c8,
    0xbf597fc7,
    0xc6e00bf3,
    0xd5a79147,
    0x06ca6351,
    0x14292967,
    0x27b70a85,
    0x2e1b2138,
    0x4d2c6dfc,
    0x53380d13,
    0x650a7354,
    0x766a0abb,
    0x81c2c92e,
    0x92722c85,
    0xa2bfe8a1,
    0xa81a664b,
    0xc24b8b70,
    0xc76c51a3,
    0xd192e819,
    0xd6990624,
    0xf40e3585,
    0x106aa070,
    0x19a4c116,
    0x1e376c08,
    0x2748774c,
    0x34b0bcb5,
    0x391c0cb3,
    0x4ed8aa4a,
    0x5b9cca4f,
    0x682e6ff3,
    0x748f82ee,
    0x78a5636f,
    0x84c87814,
    0x8cc70208,
    0x90befffa,
    0xa4506ceb,
    0xbef9a3f7,
    0xc67178f2
  ];
}
