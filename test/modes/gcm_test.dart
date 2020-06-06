// See file LICENSE for more information.

library pointycastle.test.modes.gcm_test;

import 'dart:typed_data';

import 'package:pointycastle/block/aes_fast.dart';
import 'package:pointycastle/block/modes/gcm.dart';
import 'package:pointycastle/pointycastle.dart';

import '../test/block_cipher_tests.dart';
import '../test/src/helpers.dart';

void main() {
  var paramList = [
    {
      'key': createUint8ListFromHexString('00000000000000000000000000000000'),
      'iv':  createUint8ListFromHexString('000000000000000000000000'),
      'aad': createUint8ListFromHexString(''),
      'input': '',
      'output': '',
      'mac': createUint8ListFromHexString('58e2fccefa7e3061367f1d57a4e7455a'),
    },
    {
      'key': createUint8ListFromHexString('00000000000000000000000000000000'),
      'iv':  createUint8ListFromHexString('000000000000000000000000'),
      'aad': createUint8ListFromHexString(''),
      'input': '00000000000000000000000000000000',
      'output': '0388dace60b6a392f328c2b971b2fe78',
      'mac': createUint8ListFromHexString('ab6e47d42cec13bdf53a67b21257bddf'),
    },
    {
      'key': createUint8ListFromHexString('feffe9928665731c6d6a8f9467308308'),
      'iv':  createUint8ListFromHexString('cafebabefacedbaddecaf888'),
      'aad': createUint8ListFromHexString('feedfacedeadbeeffeedfacedeadbeefabaddad2'),
      'input': 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
      'output': '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091',
      'mac': createUint8ListFromHexString('5bc94fbc3221a5db94fae95ae7121a47'),
    },
  ];

  for (var map in paramList) {
    var encrypter = GCMBlockCipher(AESFastEngine());
    var params = AEADParameters(KeyParameter(map['key'] as Uint8List), 16*8, map['iv'] as Uint8List, map['aad'] as Uint8List);
    encrypter.init(true, params);
    var result = encrypter.process(createUint8ListFromHexString(map['input'] as String));
    var pos = 0;
    for (var elem in createUint8ListFromHexString(map['output'] as String)) {
      assert (elem == result[pos++]);
    }
    pos = 0;
    for (var elem in map['mac']) {
      assert(elem == encrypter.mac[pos++]);
    }
    
    var decrypter = GCMBlockCipher(AESFastEngine())..init(false, params);
    var decrypted = formatBytesAsHexString(decrypter.process(result));
    assert(decrypted == map['input']);
  }
}
