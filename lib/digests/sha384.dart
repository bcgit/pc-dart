// See file LICENSE for more information.

library pointycastle.impl.digest.sha384;

import "dart:typed_data";

import "package:pointycastle/api.dart";
import "package:pointycastle/src/impl/long_sha2_family_digest.dart";
import "package:pointycastle/src/registry/registry.dart";

/// Implementation of SHA-384 digest.
class SHA384Digest extends LongSHA2FamilyDigest implements Digest {
  static final FactoryConfig FACTORY_CONFIG =
      new StaticFactoryConfig(Digest, "SHA-384", () => SHA384Digest());

  static const _DIGEST_LENGTH = 48;

  SHA384Digest() {
    reset();
  }

  final algorithmName = "SHA-384";
  final digestSize = _DIGEST_LENGTH;

  void reset() {
    super.reset();

    H1.set(0xcbbb9d5d, 0xc1059ed8);
    H2.set(0x629a292a, 0x367cd507);
    H3.set(0x9159015a, 0x3070dd17);
    H4.set(0x152fecd8, 0xf70e5939);
    H5.set(0x67332667, 0xffc00b31);
    H6.set(0x8eb44a87, 0x68581511);
    H7.set(0xdb0c2e0d, 0x64f98fa7);
    H8.set(0x47b5481d, 0xbefa4fa4);
  }

  int doFinal(Uint8List out, int outOff) {
    finish();

    var view = new ByteData.view(out.buffer, out.offsetInBytes, out.length);
    H1.pack(view, outOff, Endian.big);
    H2.pack(view, outOff + 8, Endian.big);
    H3.pack(view, outOff + 16, Endian.big);
    H4.pack(view, outOff + 24, Endian.big);
    H5.pack(view, outOff + 32, Endian.big);
    H6.pack(view, outOff + 40, Endian.big);

    reset();

    return _DIGEST_LENGTH;
  }
}
