import 'package:pointycastle/api.dart';
import 'package:pointycastle/block/camellia.dart';
import 'package:test/test.dart';

import '../test/src/helpers.dart';

void main() {
  group('Camellia Engine', () {
    blockCipherTest(0, CamelliaEngine(), _kp('00000000000000000000000000000000'), '80000000000000000000000000000000',
        '07923a39eb0a817d1c4d87bdb82d1f1c');

    blockCipherTest(1, CamelliaEngine(), _kp('80000000000000000000000000000000'), '00000000000000000000000000000000',
        '6c227f749319a3aa7da235a9bba05a2c');

    blockCipherTest(2, CamelliaEngine(), _kp('0123456789abcdeffedcba9876543210'), '0123456789abcdeffedcba9876543210',
        '67673138549669730857065648eabe43');

    blockCipherTest(3, CamelliaEngine(), _kp('0123456789abcdeffedcba98765432100011223344556677'),
        '0123456789abcdeffedcba9876543210', 'b4993401b3e996f84ee5cee7d79b09b9');

    blockCipherTest(4, CamelliaEngine(), _kp('000000000000000000000000000000000000000000000000'),
        '00040000000000000000000000000000', '9bca6c88b928c1b0f57f99866583a9bc');

    blockCipherTest(5, CamelliaEngine(), _kp('949494949494949494949494949494949494949494949494'),
        '636eb22d84b006381235641bcf0308d2', '94949494949494949494949494949494');

    blockCipherTest(6, CamelliaEngine(), _kp('0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff'),
        '0123456789abcdeffedcba9876543210', '9acc237dff16d76c20ef7c919e3a7509');

    blockCipherTest(7, CamelliaEngine(), _kp('4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a'),
        '057764fe3a500edbd988c5c3b56cba9a', '4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a');

    blockCipherTest(8, CamelliaEngine(), _kp('0303030303030303030303030303030303030303030303030303030303030303'),
        '7968b08aba92193f2295121ef8d75c8a', '03030303030303030303030303030303');
  });
}

KeyParameter _kp(String key) {
  return KeyParameter(createUint8ListFromHexString(key));
}
