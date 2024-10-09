import 'package:pointycastle/api.dart';
import 'package:pointycastle/block/blowfish.dart';
import 'package:test/test.dart';

import '../test/src/helpers.dart';

void main() {
  group('Blowfish Engine', () {
    blockCipherTest(0, BlowfishEngine(), _kp('0000000000000000'), '0000000000000000', '4ef997456198dd78');

    blockCipherTest(1, BlowfishEngine(), _kp('ffffffffffffffff'), 'ffffffffffffffff', '51866fd5b85ecb8a');

    blockCipherTest(2, BlowfishEngine(), _kp('3000000000000000'), '1000000000000001', '7d856f9a613063f2');

    blockCipherTest(3, BlowfishEngine(), _kp('1111111111111111'), '1111111111111111', '2466dd878b963c9d');

    blockCipherTest(4, BlowfishEngine(), _kp('0123456789abcdef'), '1111111111111111', '61f9c3802281b096');

    blockCipherTest(5, BlowfishEngine(), _kp('fedcba9876543210'), '0123456789abcdef', '0aceab0fc6a0a28d');

    blockCipherTest(6, BlowfishEngine(), _kp('7ca110454a1a6e57'), '01a1d6d039776742', '59c68245eb05282b');

    blockCipherTest(7, BlowfishEngine(), _kp('0131d9619dc1376e'), '5cd54ca83def57da', 'b1b8cc0b250f09a0');
  });
}

KeyParameter _kp(String key) {
  return KeyParameter(createUint8ListFromHexString(key));
}
