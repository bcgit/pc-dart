import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/pointycastle.dart';
import 'package:test/test.dart';

void main() {
  test('Test concatKDF', () {
    var kdf = KeyDerivator('SHA-256/ConcatKDF');
    var Z = Uint8List.fromList([
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
    var params = HkdfParameters(Z, 128);
    kdf.init(params);

    var key = kdf.process(otherData);
    expect(
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
        ]));
  });

  test("Test concatKdf A1", () {
    var z = base64Url.decode('Sq8rGLm4rEtzScmnSsY5r1n-AqBl_iBU8FxN80Uc0S0=');
    var alg = 'A256CBC-HS512';
    var _otherInfo = computerOtherInfo(alg, 512);
    var c = HkdfParameters(z, 512);
    var concatKdf = KeyDerivator('SHA-256/ConcatKDF')..init(c);
    var key = concatKdf.process(_otherInfo);
    var keyencoded = base64UrlEncode(key);
    expect(
        'pgs50IOZ6BxfqvTSie4t9OjWxGr4whiHo1v9Dti93CRiJE2PP60FojLatVVrcjg3BxpuFjnlQxL97GOwAfcwLA==',
        keyencoded);
  });

  test("Test concatKdf A2", () {
    var z = base64Url.decode('LfkHot2nGTVlmfxbgxQfMg==');
    var alg = 'A128CBC-HS256';
    var _otherInfo = computerOtherInfo(alg, 256);
    var c = HkdfParameters(z, 256);
    var concatKdf = KeyDerivator('SHA-256/ConcatKDF')..init(c);
    var key = concatKdf.process(_otherInfo);
    var keyencoded = base64UrlEncode(key);
    expect('vphyobtvExGXF7TaOvAkx6CCjHQNYamP2ET8xkhTu-0=', keyencoded);
  });
}

// Helpers for ECDH-ES
Uint8List computerOtherInfo(
    String _encryptionAlgorithmName, int _keybitLength) {
  var l = _encryptionAlgorithmName.codeUnits.length.toUnsigned(32);
  var ll = _convertToBigEndian(l);
  var a = Uint8List.fromList(_encryptionAlgorithmName.codeUnits);
//TODO: add apu, apv, fixed to empty for now
  var zero = _convertToBigEndian(0);
  var k = _convertToBigEndian(_keybitLength);
  return Uint8List.fromList([...ll, ...a, ...zero, ...zero, ...k]);
}

Uint8List _convertToBigEndian(int l) {
  var ll = Uint8List(4);
  ll[0] = (l >> 24) & 255;
  ll[1] = (l >> 16) & 255;
  ll[2] = (l >> 8) & 255;
  ll[3] = (l) & 255;
  return ll;
}
