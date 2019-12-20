// See file LICENSE for more information.

library pointycastle.impl.digest.sha512t;

import "dart:typed_data";

import "package:pointycastle/api.dart";
import "package:pointycastle/src/impl/long_sha2_family_digest.dart";
import "package:pointycastle/src/registry/registry.dart";
import "package:pointycastle/src/ufixnum.dart";

/// Implementation of SHA-512/t digest (see FIPS 180-4).
class SHA512tDigest extends LongSHA2FamilyDigest implements Digest {
  static final RegExp _NAME_REGEX = new RegExp(r"^SHA-512\/([0-9]+)$");

  /// Intended for internal use.
  static final FactoryConfig FACTORY_CONFIG = new DynamicFactoryConfig(
      Digest,
      _NAME_REGEX,
      (_, final Match match) => () {
            int bitLength = int.parse(match.group(1));
            if ((bitLength % 8) != 0) {
              throw new RegistryFactoryException(
                  "Digest length for SHA-512/t is not a multiple of 8: ${bitLength}");
            }
            return new SHA512tDigest(bitLength ~/ 8);
          });

  static final Register64 _H_MASK = new Register64(0xa5a5a5a5, 0xa5a5a5a5);

  final int digestSize;

  final _H1t = new Register64();
  final _H2t = new Register64();
  final _H3t = new Register64();
  final _H4t = new Register64();
  final _H5t = new Register64();
  final _H6t = new Register64();
  final _H7t = new Register64();
  final _H8t = new Register64();

  SHA512tDigest(this.digestSize) {
    if (digestSize >= 64) {
      throw new ArgumentError("Digest size cannot be >= 64 bytes (512 bits)");
    }
    if (digestSize == 48) {
      throw new ArgumentError(
          "Digest size cannot be 48 bytes (384 bits): use SHA-384 instead");
    }

    _generateIVs(digestSize * 8);

    reset();
  }

  String get algorithmName => "SHA-512/${digestSize * 8}";

  void reset() {
    super.reset();

    H1.set(_H1t);
    H2.set(_H2t);
    H3.set(_H3t);
    H4.set(_H4t);
    H5.set(_H5t);
    H6.set(_H6t);
    H7.set(_H7t);
    H8.set(_H8t);
  }

  int doFinal(Uint8List out, int outOff) {
    finish();

    var tmp = new Uint8List(64);

    var view = new ByteData.view(tmp.buffer, tmp.offsetInBytes, tmp.length);
    H1.pack(view, 0, Endian.big);
    H2.pack(view, 8, Endian.big);
    H3.pack(view, 16, Endian.big);
    H4.pack(view, 24, Endian.big);
    H5.pack(view, 32, Endian.big);
    H6.pack(view, 40, Endian.big);
    H7.pack(view, 48, Endian.big);
    H8.pack(view, 56, Endian.big);

    out.setRange(outOff, outOff + digestSize, tmp);

    reset();

    return digestSize;
  }

  void _generateIVs(int bitLength) {
    H1
      ..set(0x6a09e667, 0xf3bcc908)
      ..xor(_H_MASK);
    H2
      ..set(0xbb67ae85, 0x84caa73b)
      ..xor(_H_MASK);
    H3
      ..set(0x3c6ef372, 0xfe94f82b)
      ..xor(_H_MASK);
    H4
      ..set(0xa54ff53a, 0x5f1d36f1)
      ..xor(_H_MASK);
    H5
      ..set(0x510e527f, 0xade682d1)
      ..xor(_H_MASK);
    H6
      ..set(0x9b05688c, 0x2b3e6c1f)
      ..xor(_H_MASK);
    H7
      ..set(0x1f83d9ab, 0xfb41bd6b)
      ..xor(_H_MASK);
    H8
      ..set(0x5be0cd19, 0x137e2179)
      ..xor(_H_MASK);

    updateByte(0x53);
    updateByte(0x48);
    updateByte(0x41);
    updateByte(0x2D);
    updateByte(0x35);
    updateByte(0x31);
    updateByte(0x32);
    updateByte(0x2F);

    if (bitLength > 100) {
      updateByte(bitLength ~/ 100 + 0x30);
      bitLength = bitLength % 100;
      updateByte(bitLength ~/ 10 + 0x30);
      bitLength = bitLength % 10;
      updateByte(bitLength + 0x30);
    } else if (bitLength > 10) {
      updateByte(bitLength ~/ 10 + 0x30);
      bitLength = bitLength % 10;
      updateByte(bitLength + 0x30);
    } else {
      updateByte(bitLength + 0x30);
    }

    finish();

    _H1t.set(H1);
    _H2t.set(H2);
    _H3t.set(H3);
    _H4t.set(H4);
    _H5t.set(H5);
    _H6t.set(H6);
    _H7t.set(H7);
    _H8t.set(H8);
  }
}
