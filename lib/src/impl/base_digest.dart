// See file LICENSE for more information.

library pointycastle.src.impl.base_digest;

import "dart:typed_data";

import "package:pointycastle/api.dart";

/// Base implementation of [Digest] which provides shared methods.
abstract class BaseDigest implements Digest {
  Uint8List process(Uint8List data) {
    update(data, 0, data.length);
    var out = new Uint8List(digestSize);
    var len = doFinal(out, 0);
    return out.sublist(0, len);
  }
}
