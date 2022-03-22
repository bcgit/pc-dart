import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:pointycastle/src/utils.dart';
import 'package:test/test.dart';

void main() {
  test("Test concatKDF", () {
    var kdf = KeyDerivator("SHA-256/ConcatKDF");
    var Z = decodeBigInt([
      158,
      86,
      217,
      29,
      129,
      113,
      53,
      211,
      114,
      131,
      66,
      131,
      191,
      132,
      38,
      156,
      251,
      49,
      110,
      163,
      218,
      128,
      106,
      72,
      246,
      218,
      167,
      121,
      140,
      254,
      144,
      196
    ]);
    var otherData = Uint8List.fromList([
      0,
      0,
      0,
      7,
      65,
      49,
      50,
      56,
      71,
      67,
      77,
      0,
      0,
      0,
      5,
      65,
      108,
      105,
      99,
      101,
      0,
      0,
      0,
      3,
      66,
      111,
      98,
      0,
      0,
      0,
      128
    ]);
    var params = ConcatKDFParameters(Z, 128, otherData);
    kdf.init(params);

    var key = kdf.process(Uint8List(0));
    assert(ListEquality().equals(
        key,
        Uint8List.fromList([
          86,
          170,
          141,
          234,
          248,
          35,
          109,
          32,
          92,
          34,
          40,
          205,
          113,
          167,
          16,
          26
        ])));
  });
}
