// See file LICENSE for more information.

library test.modes.gcm_test;

import 'dart:typed_data';

import 'package:pointycastle/block/aes_fast.dart';
import 'package:pointycastle/block/modes/ccm.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:test/test.dart';

import '../test/src/helpers.dart';

void main() {
  var paramList = [
    {
      'name': 'Test Case 1',
      'key': createUint8ListFromHexString('404142434445464748494a4b4c4d4e4f'),
      'iv': createUint8ListFromHexString('10111213141516'),
      'aad': createUint8ListFromHexString('0001020304050607'),
      'input': '20212223',
      'output': '7162015b4dac255d',
      'mac': createUint8ListFromHexString('6084341b')
    },
    {
      'name': 'Test Case 2',
      'key': createUint8ListFromHexString('404142434445464748494a4b4c4d4e4f'),
      'iv': createUint8ListFromHexString('1011121314151617'),
      'aad': createUint8ListFromHexString('000102030405060708090a0b0c0d0e0f'),
      'input': '202122232425262728292a2b2c2d2e2f',
      'output': 'd2a1f0e051ea5f62081a7792073d593d1fc64fbfaccd',
      'mac': createUint8ListFromHexString('7f479ffca464')
    },
    {
      'name': 'Test Case 3',
      'key': createUint8ListFromHexString('404142434445464748494a4b4c4d4e4f'),
      'iv': createUint8ListFromHexString('101112131415161718191a1b'),
      'aad': createUint8ListFromHexString('000102030405060708090a0b0c0d0e0f10111213'),
      'input': '202122232425262728292a2b2c2d2e2f3031323334353637',
      'output': 'e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5484392fbc1b09951',
      'mac': createUint8ListFromHexString('67c99240c7d51048')
    },
    {
      'name': 'Test Case 4',
      'key': createUint8ListFromHexString('404142434445464748494a4b4c4d4e4f'),
      'iv': createUint8ListFromHexString('101112131415161718191a1b1c'),
      'aad': createUint8ListFromHexString(
          '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'),
      'input':
      '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f',
      'output':
      '69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72b4ac6bec93e8598e7f0dadbcea5b',
      'mac': createUint8ListFromHexString('f4dd5d0ee404617225ffe34fce91')
    },
  ];

  group('AES-CCM', () {
    for (var map in paramList) {
      test(map['name'], () {
        var encrypter = CCMBlockCipher(AESFastEngine());
        var params = AEADParameters(KeyParameter((map['key'] as Uint8List)),
            16 * 8, (map['iv'] as Uint8List), (map['aad'] as Uint8List));
        encrypter.init(true, params);
        var result = encrypter
            .process(createUint8ListFromHexString(map['input'] as String));

        expect(result, orderedEquals(createUint8ListFromHexString(map['output'] as String)));
        expect(encrypter.mac, orderedEquals(map['mac'] as Uint8List));

        var decrypter = CCMBlockCipher(AESFastEngine())..init(false, params);
        var decrypted = formatBytesAsHexString(decrypter.process(result));
        expect(decrypted, map['input']);
      });
    }
  });
}