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

void main() {
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
