// See file LICENSE for more information.

library src.utils_test;

import 'dart:math';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:pointycastle/src/utils.dart';

Random random = Random();

Uint8List randomBytes(int length) {
  return Uint8List.fromList(List<int>.generate(length, (_) {
    return random.nextInt(0xff + 1);
  }, growable: false));
}

void testBigIntEncoding() {
  group('BigInt utility ', () {
    test('twos compliment encoding', () {
      BigInt bi1 = BigInt.zero - BigInt.from(128);

      Uint8List out = encodeBigInt(bi1);
      expect([128], equals(out));
      out = encodeBigIntAsUnsigned(bi1);
      expect([128], equals(out));

      BigInt bi2 = BigInt.from(128);
      out = encodeBigInt(bi2); // [0,128]
      expect([0, 128], equals(out));
      out = encodeBigIntAsUnsigned(bi2);
      expect([128], equals(out));
    });
  });
}

void main() {
  testBigIntEncoding();

  test('decode encode roundtrip', () {
    for (var size = 1; size < 100; size++) {
      var bytes = randomBytes(size);

      // Remove leading zeroes.
      while (bytes.isNotEmpty && bytes[0] == 0x0) {
        bytes = bytes.sublist(1, bytes.length);
      }

      if (bytes.isEmpty) {
        continue;
      }

      var decoded = decodeBigInt(bytes);
      var encoded = encodeBigInt(decoded);
      expect(encoded, equals(bytes));
    }
  });
}
