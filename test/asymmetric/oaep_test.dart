// See file LICENSE for more information.

library pointycastle.test.asymmetric.oaep_test;

import 'dart:typed_data';

import "package:test/test.dart";

import "package:pointycastle/pointycastle.dart";
import "package:pointycastle/src/registry/registry.dart";
import 'package:pointycastle/asymmetric/api.dart';
import 'package:pointycastle/asymmetric/oaep.dart';
import 'package:pointycastle/asymmetric/rsa.dart';
import 'package:pointycastle/src/utils.dart';

import "../test/src/fixed_secure_random.dart";
import '../test/src/helpers.dart';
import "../test/src/null_asymmetric_block_cipher.dart";

//================================================================
/// Tests for RSA-OAEP with a known-correct test vector.
///
/// Test RSA-OAEP using the test vector from "RSAES-OAEP Encryption Scheme:
/// Algorithm specification and supporting documentation", published by
/// RSA Laboratories in 2000.
///
/// A copy was found here:
/// https://www.inf.pucrs.br/~calazans/graduate/TPVLSI_I/RSA-oaep_spec.pdf

void rsaOaepStandardTests() {
  // RSA key information

  // n, the modulus:
  final n = decodeBigInt(createUint8ListFromHexString(
      'bb f8 2f 09 06 82 ce 9c 23 38 ac 2b 9d a8 71 f7 36 8d 07 ee d4 10 43 a4'
      '40 d6 b6 f0 74 54 f5 1f b8 df ba af 03 5c 02 ab 61 ea 48 ce eb 6f cd 48'
      '76 ed 52 0d 60 e1 ec 46 19 71 9d 8a 5b 8b 80 7f af b8 e0 a3 df c7 37 72'
      '3e e6 b4 b7 d9 3a 25 84 ee 6a 64 9d 06 09 53 74 88 34 b2 45 45 98 39 4e'
      'e0 aa b1 2d 7b 61 a5 1f 52 7a 9a 41 f6 c1 68 7f e2 53 72 98 ca 2a 8f 59'
      '46 f8 e5 fd 09 1d bd cb'));

  // e, the public exponent
  final e = decodeBigInt(createUint8ListFromHexString('11'));

  // p, the first prime factor of n
  final p = decodeBigInt(createUint8ListFromHexString(
      'ee cf ae 81 b1 b9 b3 c9 08 81 0b 10 a1 b5 60 01 99 eb 9f 44 ae f4 fd a4'
      '93 b8 1a 9e 3d 84 f6 32 12 4e f0 23 6e 5d 1e 3b 7e 28 fa e7 aa 04 0a 2d'
      '5b 25 21 76 45 9d 1f 39 75 41 ba 2a 58 fb 65 99'));

  // q, the second prime factor of n:
  final q = decodeBigInt(createUint8ListFromHexString(
      'c9 7f b1 f0 27 f4 53 f6 34 12 33 ea aa d1 d9 35 3f 6c 42 d0 88 66 b1 d0'
      '5a 0f 20 35 02 8b 9d 86 98 40 b4 16 66 b4 2e 92 ea 0d a3 b4 32 04 b5 cf'
      'ce 33 52 52 4d 04 16 a5 a4 41 e7 00 af 46 15 03'));

  // dP , p’s exponent:
  final dP = decodeBigInt(createUint8ListFromHexString(
      '54 49 4c a6 3e ba 03 37 e4 e2 40 23 fc d6 9a 5a eb 07 dd dc 01 83 a4 d0'
      'ac 9b 54 b0 51 f2 b1 3e d9 49 09 75 ea b7 74 14 ff 59 c1 f7 69 2e 9a 2e'
      '20 2b 38 fc 91 0a 47 41 74 ad c9 3c 1f 67 c9 81'));

  // dQ, q’s exponent:
  final dQ = decodeBigInt(createUint8ListFromHexString(
      '47 1e 02 90 ff 0a f0 75 03 51 b7 f8 78 86 4c a9 61 ad bd 3a 8a 7e 99 1c'
      '5c 05 56 a9 4c 31 46 a7 f9 80 3f 8f 6f 8a e3 42 e9 31 fd 8a e4 7a 22 0d'
      '1b 99 a4 95 84 98 07 fe 39 f9 24 5a 98 36 da 3d'));

  // qInv, the CRT coefficient:
  final qInv = decodeBigInt(createUint8ListFromHexString(
      'b0 6c 4f da bb 63 01 19 8d 26 5b db ae 94 23 b3 80 f2 71 f7 34 53 88 50'
      '93 07 7f cd 39 e2 11 9f c9 86 32 15 4f 58 83 b1 67 a9 67 bf 40 2b 4e 9e'
      '2e 0f 96 56 e6 98 ea 36 66 ed fb 25 79 80 39 f7'));

  //----------------
  // Encryption

  // M, the message to be encrypted:
  final message = createUint8ListFromHexString(
      'd4 36 e9 95 69 fd 32 a7 c8 a0 5b bc 90 d3 2c 49');

  // P , encoding parameters: NULL
  // ignore: unused_local_variable
  final params = null;

  // pHash = Hash(P ):
  // ignore: unused_local_variable
  final pHash = createUint8ListFromHexString(
      'da 39 a3 ee 5e 6b 4b 0d 32 55 bf ef 95 60 18 90 af d8 07 09');

  // DB = pHash∥PS∥01∥M:
  // ignore: unused_local_variable
  final db = createUint8ListFromHexString(
      'da 39 a3 ee 5e 6b 4b 0d 32 55 bf ef 95 60 18 90 af d8 07 09 00 00 00 00'
      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 d4 36 e9 95 69'
      'fd 32 a7 c8 a0 5b bc 90 d3 2c 49');

  // seed, a random octet string:
  // ignore: unused_local_variable
  final seed = createUint8ListFromHexString(
      'aa fd 12 f6 59 ca e6 34 89 b4 79 e5 07 6d de c2 f0 6c b5 8f');

  // dbMask = M GF (seed , 107):
  // ignore: unused_local_variable
  final dbMask = createUint8ListFromHexString(
      '06 e1 de b2 36 9a a5 a5 c7 07 d8 2c 8e 4e 93 24 8a c7 83 de e0 b2 c0 46'
      '26 f5 af f9 3e dc fb 25 c9 c2 b3 ff 8a e1 0e 83 9a 2d db 4c dc fe 4f f4'
      '77 28 b4 a1 b7 c1 36 2b aa d2 9a b4 8d 28 69 d5 02 41 21 43 58 11 59 1b'
      'e3 92 f9 82 fb 3e 87 d0 95 ae b4 04 48 db 97 2f 3a c1 4e af f4 9c 8c 3b'
      '7c fc 95 1a 51 ec d1 dd e6 12 64');

  // maskedDB = DB ⊕ dbMask:
  // ignore: unused_local_variable
  final maskedDB = createUint8ListFromHexString(
      'dc d8 7d 5c 68 f1 ee a8 f5 52 67 c3 1b 2e 8b b4 25 1f 84 d7 e0 b2 c0 46'
      '26 f5 af f9 3e dc fb 25 c9 c2 b3 ff 8a e1 0e 83 9a 2d db 4c dc fe 4f f4'
      '77 28 b4 a1 b7 c1 36 2b aa d2 9a b4 8d 28 69 d5 02 41 21 43 58 11 59 1b'
      'e3 92 f9 82 fb 3e 87 d0 95 ae b4 04 48 db 97 2f 3a c1 4f 7b c2 75 19 52'
      '81 ce 32 d2 f1 b7 6d 4d 35 3e 2d');

  // seedMask = M GF (maskedDB, 20):
  // ignore: unused_local_variable
  final seedMask = createUint8ListFromHexString(
      '41 87 0b 5a b0 29 e6 57 d9 57 50 b5 4c 28 3c 08 72 5d be a9');

  // maskedSeed = seed ⊕ seedMask:
  // ignore: unused_local_variable
  final maskedSeed = createUint8ListFromHexString(
      'eb 7a 19 ac e9 e3 00 63 50 e3 29 50 4b 45 e2 ca 82 31 0b 26');

  // EM = maskedSeed∥maskedDB:
  final em = createUint8ListFromHexString(
      'eb 7a 19 ac e9 e3 00 63 50 e3 29 50 4b 45 e2 ca 82 31 0b 26 dc d8 7d 5c'
      '68 f1 ee a8 f5 52 67 c3 1b 2e 8b b4 25 1f 84 d7 e0 b2 c0 46 26 f5 af f9'
      '3e dc fb 25 c9 c2 b3 ff 8a e1 0e 83 9a 2d db 4c dc fe 4f f4 77 28 b4 a1'
      'b7 c1 36 2b aa d2 9a b4 8d 28 69 d5 02 41 21 43 58 11 59 1b e3 92 f9 82'
      'fb 3e 87 d0 95 ae b4 04 48 db 97 2f 3a c1 4f 7b c2 75 19 52 81 ce 32 d2'
      'f1 b7 6d 4d 35 3e 2d');

  // C, the RSA encryption of EM:
  final ciphertext = createUint8ListFromHexString(
      '12 53 e0 4d c0 a5 39 7b b4 4a 7a b8 7e 9b f2 a0 39 a3 3d 1e 99 6f c8 2a'
      '94 cc d3 00 74 c9 5d f7 63 72 20 17 06 9e 52 68 da 5d 1c 0b 4f 87 2c f6'
      '53 c1 1d f8 23 14 a6 79 68 df ea e2 8d ef 04 bb 6d 84 b1 c3 1d 65 4a 19'
      '70 e5 78 3b d6 eb 96 a0 24 c2 ca 2f 4a 90 fe 9f 2e f5 c9 c1 40 e5 bb 48'
      'da 95 36 ad 87 00 c8 4f c9 13 0a de a7 4e 55 8d 51 a7 4d df 85 d8 b5 0d'
      'e9 68 38 d6 06 3e 09 55');

  //----------------
  // Decryption

  // c mod p (c is the integer value of C):
  // ignore: unused_local_variable
  final cModP = createUint8ListFromHexString(
      'de 63 d4 72 35 66 fa a7 59 bf e4 08 82 1d d5 25 72 ec 92 85 4d df 87 a2'
      'b6 64 d4 4d aa 37 ca 34 6a 05 20 3d 82 ff 2d e8 e3 6c ec 1d 34 f9 8e b6'
      '05 e2 a7 d2 6d e7 af 36 9c e4 ec ae 14 e3 56 33');

  // c mod q:
  // ignore: unused_local_variable
  final cModQ = createUint8ListFromHexString(
      'a2 d9 24 de d9 c3 6d 62 3e d9 a6 5b 5d 86 2c fb ec 8b 19 9c 64 27 9c 54'
      '14 e6 41 19 6e f1 c9 3c 50 7a 9b 52 13 88 1a ad 05 b4 cc fa 02 8a c1 ec'
      '61 42 09 74 bf 16 25 83 6b 0b 7d 05 fb b7 53 36');

  // m1 =cdP modp=(cmodp)dP modp:
  // ignore: unused_local_variable
  final m1 = createUint8ListFromHexString(
      '89 6c a2 6c d7 e4 87 1c 7f c9 68 a8 ed ea 11 e2 71 82 4f 0e 03 65 52 17'
      '94 f1 e9 e9 43 b4 a4 4b 57 c9 e3 95 a1 46 74 78 f5 26 49 6b 4b b9 1f 1c'
      'ba ea 90 0f fc 60 2c f0 c6 63 6e ba 84 fc 9f f7');

  //m2 =cdQ modq=(cmodq)dQ modq:
  // ignore: unused_local_variable
  final m2 = createUint8ListFromHexString(
      '4e bb 22 75 85 f0 c1 31 2d ca 19 e0 b5 41 db 14 99 fb f1 4e 27 0e 69 8e'
      '23 9a 8c 27 a9 6c da 9a 74 09 74 de 93 7b 5c 9c 93 ea d9 46 2c 65 75 02'
      '1a 23 d4 64 99 dc 9f 6b 35 89 75 59 60 8f 19 be');

  // h=(m1 −m2)qInvmodp:
  // ignore: unused_local_variable
  final h = createUint8ListFromHexString(
      '01 2b 2b 24 15 0e 76 e1 59 bd 8d db 42 76 e0 7b fa c1 88 e0 8d 60 47 cf'
      '0e fb 8a e2 ae bd f2 51 c4 0e bc 23 dc fd 4a 34 42 43 94 ad a9 2c fc be'
      '1b 2e ff bb 60 fd fb 03 35 9a 95 36 8d 98 09 25');

  //----------------------------------------------------------------
  // Create Pointy Castle [RSAPublicKey] and [RSAPrivateKey] objects.

  // Derive the private exponent (d) from values provided in the test vector.

  final phi = (p - BigInt.one) * (q - BigInt.one);

  final privateExponent = e.modInverse(phi);

  // Instantiate the RSA key pair objects

  final publicKey = RSAPublicKey(n, e);
  final privateKey = RSAPrivateKey(n, privateExponent, p, q);

  //----------------

  test('RSA key pair is valid', () {
    // Some correctness checks for the RSA public-key values.
    //
    // This test should never fail, since the values are known to be correct.

    expect(p * q, equals(n)); // modulus = p * q

    // dP = (1/e) mod (p-1)
    expect(e.modInverse(p - BigInt.one), equals(dP));

    // dQ = (1/e) mod (q-1)
    expect(e.modInverse(q - BigInt.one), equals(dQ));

    // qInv = (1/q) mod p  where p > q
    expect(q.modInverse(p), equals(qInv));

    expect((e * privateExponent) % phi, equals(BigInt.one));
  });

  //----------------------------------------------------------------

  test('EME-OAEP encoding operation', () {
    // This test is actually redundant.
    //
    // If the following "encryption" test passes, then the encoding operation
    // would have also worked. But since we can make replace the [RSAEngine]
    // with the [NullAsymmetricBlockCipher] that does nothing, we can use it to
    // examine the EME-OAEP encoded message (called "EM" in RFC 2437), before it
    // normally gets encrypted.
    //
    // If there is a bug in the underlying asymmetric encryption (i.e. in the
    // [RSAEngine], this test will succeed when the encryption test will fail.
    // If there is a bug in the EME-OAEP encoding operation, then this test and
    // the following encryption test will both fail. It is impossible for this
    // test to fail and the encryption test to pass.

    // Can't instantiate using AsymmetricBlockCipher('Null/OAEP'), because the
    // default [NullAsymmetricBlockCipher] has block lengths of 70 instead of
    // 127 (which is necessary for this to work properly). So must use its
    // constructor and pass in 127 for the two block lengths.

    final encryptor = OAEPEncoding(NullAsymmetricBlockCipher(127, 127));

    encryptor.init(
        true,
        ParametersWithRandom(PublicKeyParameter<RSAPublicKey>(publicKey),
            FixedSecureRandom()..seed(KeyParameter(seed))));

    // Pretend to encrypt the test [message] value

    final output = Uint8List(encryptor.outputBlockSize);

    final size = encryptor.processBlock(message, 0, message.length, output, 0);
    expect(size, equals(encryptor.outputBlockSize));

    // The output should be the unencrypted EM (since Null cipher does nothing)

    expect(output, equals(em));
  });

  //----------------------------------------------------------------

  test('encryption', () {
    // Create the OAEPEncoding and initialize it with the publicKey and a
    // special SecureRandom implementation that always returns the fixed [seed]
    // value, so the produced ciphertext is deterministic and can match the
    // expected value. DO NOT DO THIS IN PRODUCTION. This is insecure and is
    // done only for testing purposes.

    registry.register(FixedSecureRandom.FACTORY_CONFIG); // register "Fixed"

    final encryptor = AsymmetricBlockCipher('RSA/OAEP'); // using registry

    encryptor.init(
        true, // true = for encryption
        ParametersWithRandom(PublicKeyParameter<RSAPublicKey>(publicKey),
            SecureRandom('Fixed')..seed(KeyParameter(seed))));

    // Encrypt the test [message] value

    final output = Uint8List(encryptor.outputBlockSize);

    final size = encryptor.processBlock(message, 0, message.length, output, 0);
    expect(size, equals(encryptor.outputBlockSize));

    // The ciphertext should be the expected test [ciphertext] value

    expect(output, equals(ciphertext));
  });

  //----------------------------------------------------------------

  test('decryption', () {
    final decryptor = OAEPEncoding(RSAEngine()); // without using the registry

    decryptor.init(false, PrivateKeyParameter<RSAPrivateKey>(privateKey));

    // Decrypt the test [ciphertext] value

    final outBuf = Uint8List(decryptor.outputBlockSize);

    final outputSize =
        decryptor.processBlock(ciphertext, 0, ciphertext.length, outBuf, 0);
    final decrypted = outBuf.sublist(0, outputSize);

    // The decrypted message should be the expected test [message] value

    expect(decrypted, equals(message));
  });

  //----------------------------------------------------------------

  test('tampered ciphertext detected', () {
    final decryptor = OAEPEncoding(RSAEngine()); // without using the registry

    decryptor.init(false, PrivateKeyParameter<RSAPrivateKey>(privateKey));

    // Try tampering with every bit in the ciphertext (128 bytes = 1024 bits)

    for (var bitPos = 0; bitPos < ciphertext.length * 8; bitPos++) {
      // Create a copy of the ciphertext that has been tampered with

      final tamperedCiphertext = Uint8List.fromList(ciphertext);
      tamperedCiphertext[bitPos ~/ 8] ^= 0x01 << (bitPos % 8); // flip a bit

      // Try to decrypt it: expecting it to always fail

      try {
        final outBuf = Uint8List(decryptor.outputBlockSize);

        // ignore: unused_local_variable
        final _outputSize = decryptor.processBlock(
            tamperedCiphertext, 0, tamperedCiphertext.length, outBuf, 0);
        fail('tampered with ciphertext still decrypted');

        // final decrypted = outBuf.sublist(0, outputSize);
        // expect(decrypted, equals(message));

      } on ArgumentError catch (e) {
        expect(e.message, equals('decoding error'));
      }
    }
  });
}

//================================================================

void main() {
  rsaOaepStandardTests();
}
