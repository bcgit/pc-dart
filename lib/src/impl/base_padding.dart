// See file LICENSE for more information.

library pointycastle.src.impl.base_padding;

import "dart:typed_data";

import "package:pointycastle/api.dart";

/// Base implementation of [Padding] which provides shared methods.
abstract class BasePadding implements Padding {
  Uint8List process(bool pad, Uint8List data) {
    if (pad) {
      var out = new Uint8List.fromList(data);
      var len = addPadding(out, 0);
      return out;
    } else {
      var len = padCount(data);
      return new Uint8List.fromList(data.sublist(0, len));
    }
  }
}
