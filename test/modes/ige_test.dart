// See file LICENSE for more information.

library test.modes.ige_test;

import 'package:pointycastle/pointycastle.dart';

import '../test/block_cipher_tests.dart';
import '../test/src/helpers.dart';

void main() {
  final key1 =
      createUint8ListFromHexString('000102030405060708090A0B0C0D0E0F'.toLowerCase());
  final iv1 = createUint8ListFromHexString(
      '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F'.toLowerCase());
  final params1 = ParametersWithIV(KeyParameter(key1), iv1);

  final data1 = String.fromCharCodes(createUint8ListFromHexString(
      '0000000000000000000000000000000000000000000000000000000000000000'));
  final ct1 = '1A8519A6557BE652E9DA8E43DA4EF4453CF456B4CA488AA383C79C98B34797CB'.toLowerCase();

  runBlockCipherTests(BlockCipher('AES/IGE'), params1, [
    data1,
    ct1
  ]);
}
