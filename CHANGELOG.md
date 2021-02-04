Changelog
=========

#### Version 3.0.0-nullsafety.2 (2021-02-05)

* Ports this library to non-nullable-by-default, a new feature in the Dart language
* This is a breaking change: client code (libraries and apps) will have to migrate as well to use new releases of this
  library.
* This library's existing APIs should not have changed functionally from Version 2.0.1; any such change should be
  reported at https://github.com/bcgit/pc-dart/issues
* The block cipher modes IGE and CCM were also added in this update.
* More info about migration: https://dart.dev/null-safety/migration-guide
* More info about null safety: https://dart.dev/null-safety

#### Version 3.0.0-nullsafety.1

* not published

#### Version 3.0.0-nullsafety.0

* not published

#### Version 2.0.1 (2021-01-16)

* Bug fix, ASN1Utils
* Removal of 'dart:io'
* RSAPrivateKey calculates the public exponent from the other values.

The previous BigInt handling functions in the util package now treat encoded BigInts as twos compliment numbers, this
may cause sudden unexpected failures if a number is suddenly negative. Users are advised to review their use of
decodeBigInt and encodeBigInt.

**utils.dart:**
- decodeBigInt is twos compliment.
- encodeBigInt is twos compliment and adds padding to preserve sign.
- encodeBigIntAsUnsigned writes the magnitude without any padding.
- decodeBigIntWithSign allows the specification of an arbitrary sign.
- Previous uses of decodeBigInt where the expectation is an unsigned integer have been updated with
  decodeBigIntWithSign(1, magnitude).

#### Version 2.0.0 (2020-10-02)

* No changes from 2.0.0-rc2

#### Version 2.0.0-rc2 (2020-09-25)

* Linter Fixes
* Updates to ASN1 API

#### Version 2.0.0-rc1 (2020-09-11) (Dart SDK version 2.1.1)::q!

* Fixed OAEPEncoding and PKCS1Encoding to use provided output offset value.
* Fixed RSA block length and offset checks in RSAEngine.processBlock.
* Fixed RSASigner.verifySignature to return false when signature is bad.
* Add HKDF support (IETF RFC 5869)
* Add Poly1305, ChaCha20, ChaCha7539, AES-GCM, SHA3, Keccak, RSA/PSS
* Add CSHAKE, SHAKE
* Fixed randomly occurring bug with OAEP decoding.
* Added NormalizedECDSASigner that wraps ECDSASigner to guarantee an ecdsa signature in lower-s form. (Enforcement on verification supported).
* Reduce copies in CBC mode.
* Linter issues fixed.
* FixedSecureRandom to use seed only once.
* ASN1 - BOOLEAN, INTEGER, BIT_STRING, OCTET_STRING, NULL, OBJECT_IDENTIFIER, 
  ENUMERATED, UTF8_STRING, SEQUENCE, SET, PRINTABLE_STRING, IA5_STRING & UTC_TIME
* ASN1 Encoding - DER & BER
* RSA Keys - Private Key carries public key exponent, added publicExponent and privateExponent where necessary
  and deprecated single variable getters in for those values.

##### Thanks, Steven
 At this release the Point Castle Crypto API has been fully handed over to the 
 Legion of the Bouncy Castle Inc. Steven Roose, it is no small thing to single headedly 
 manage a cryptography API and your effort is rightfully respected by the Pointy Castle user 
 base. We would like to thank you for your trust in us to carry the project forward, and we
 wish you all the best!
  
  
#### Version 1.0.2 (2019-11-15)

* Add non-Keccak SHA3 support
* Add CMAC support ("AES/CMAC")
* Add ISO7816-4 padding support
* Fixes in CBCBlockCipherMac and CMac

#### Version 1.0.1 (2019-02-20)

* Add Blake2b support

#### Version 1.0.0 (2018-12-17) (Dart SDK version 2.0)

* Support Dart 2 and Strong Mode
* Migrate from `package:bignum.BigInteger` to `dart:core.BigInt`
* Remove Quiver and fixnum dependency
* OAEP encoding for block ciphers


#### Version 0.10.0 (2016-02-04) (Dart SDK version 0.14.0)

* First Pointy Castle release.

* Reorganised file structure.

* Completely new Registry implementation that dynamically loads imported implementations using reflection.
  It is explained in [this commit](https://github.com/PointyCastle/pointycastle/commit/2da75e5a8d7bdbf95d08329add9f13b9070b75d4).

* Migrated from unittest to test package.


### cipher releases

#### Version 0.8.0 (2014-??-??) (Dart SDK version ???)

* **[bug 80]** PaddedBlockCipher doesn't add padding when data length is a multiple of the block 
                size. This fix introduces a **BREAKING CHANGE** in PaddedBlockCipher specification.
                Read its API documentation to know about the changes.


#### Version 0.7.0 (2014-03-22) (Dart SDK version 1.3.0-dev.5.2)

* **[enh 15]** Implement stream cipher benchmarks.
* **[enh 64]** Benchmark and optimize digests.
* **[enh 74]** Make SHA-3 usable in terms of speed.

* **[bug 67]** Removed some unused code.
* **[bug 68]** Fix process() method of PaddedBlockCipher.
* **[bug 75]** Remove a registry dependency in the Scrypt algorithm.
