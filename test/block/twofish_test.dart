import 'package:pointycastle/api.dart';
import 'package:pointycastle/block/modes/cbc.dart';
import 'package:pointycastle/block/twofish.dart';
import 'package:test/test.dart';

import '../test/src/helpers.dart';

void main() {
  group('Twofish Engine', () {
    final input = '000102030405060708090a0b0c0d0e0f';

    blockCipherTest(0, TwofishEngine(), _kp('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'), input,
        '8ef0272c42db838bcf7b07af0ec30f38');

    blockCipherTest(1, TwofishEngine(), _kp('000102030405060708090a0b0c0d0e0f1011121314151617'), input,
        '95accc625366547617f8be4373d10cd7');

    blockCipherTest(
        2, TwofishEngine(), _kp('000102030405060708090a0b0c0d0e0f'), input, '9fb63337151be9c71306d159ea7afaa4');

    blockCipherTest(
        3,
        CBCBlockCipher(TwofishEngine()),
        _kpWithIV('0123456789abcdef1234567890abcdef', '1234567890abcdef0123456789abcdef'),
        input,
        'd6bfdbb2090562e960273783127e2658');
  });
}

KeyParameter _kp(String key) {
  return KeyParameter(createUint8ListFromHexString(key));
}

ParametersWithIV<KeyParameter> _kpWithIV(String key, String iv) {
  return ParametersWithIV(_kp(key), createUint8ListFromHexString(iv));
}
