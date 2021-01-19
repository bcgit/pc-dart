library src.registry.impl;

import 'package:pointycastle/asymmetric/oaep.dart';
import 'package:pointycastle/asymmetric/pkcs1.dart';
import 'package:pointycastle/asymmetric/rsa.dart';
import 'package:pointycastle/block/aes_fast.dart';
import 'package:pointycastle/block/modes/cbc.dart';
import 'package:pointycastle/block/modes/cfb.dart';
import 'package:pointycastle/block/modes/ctr.dart';
import 'package:pointycastle/block/modes/ecb.dart';
import 'package:pointycastle/block/modes/gcm.dart';
import 'package:pointycastle/block/modes/gctr.dart';
import 'package:pointycastle/block/modes/ofb.dart';
import 'package:pointycastle/block/modes/sic.dart';
import 'package:pointycastle/digests/blake2b.dart';
import 'package:pointycastle/digests/keccak.dart';
import 'package:pointycastle/digests/md2.dart';
import 'package:pointycastle/digests/md4.dart';
import 'package:pointycastle/digests/md5.dart';
import 'package:pointycastle/digests/ripemd128.dart';
import 'package:pointycastle/digests/ripemd160.dart';
import 'package:pointycastle/digests/ripemd256.dart';
import 'package:pointycastle/digests/ripemd320.dart';
import 'package:pointycastle/digests/sha1.dart';
import 'package:pointycastle/digests/sha224.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/sha3.dart';
import 'package:pointycastle/digests/sha384.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/digests/sha512t.dart';
import 'package:pointycastle/digests/shake.dart';
import 'package:pointycastle/digests/cshake.dart';
import 'package:pointycastle/digests/tiger.dart';
import 'package:pointycastle/digests/whirlpool.dart';
import 'package:pointycastle/ecc/curves/brainpoolp160r1.dart';
import 'package:pointycastle/ecc/curves/brainpoolp160t1.dart';
import 'package:pointycastle/ecc/curves/brainpoolp192r1.dart';
import 'package:pointycastle/ecc/curves/brainpoolp192t1.dart';
import 'package:pointycastle/ecc/curves/brainpoolp224r1.dart';
import 'package:pointycastle/ecc/curves/brainpoolp224t1.dart';
import 'package:pointycastle/ecc/curves/brainpoolp256r1.dart';
import 'package:pointycastle/ecc/curves/brainpoolp256t1.dart';
import 'package:pointycastle/ecc/curves/brainpoolp320r1.dart';
import 'package:pointycastle/ecc/curves/brainpoolp320t1.dart';
import 'package:pointycastle/ecc/curves/brainpoolp384r1.dart';
import 'package:pointycastle/ecc/curves/brainpoolp384t1.dart';
import 'package:pointycastle/ecc/curves/brainpoolp512r1.dart';
import 'package:pointycastle/ecc/curves/brainpoolp512t1.dart';
import 'package:pointycastle/ecc/curves/gostr3410_2001_cryptopro_a.dart';
import 'package:pointycastle/ecc/curves/gostr3410_2001_cryptopro_b.dart';
import 'package:pointycastle/ecc/curves/gostr3410_2001_cryptopro_c.dart';
import 'package:pointycastle/ecc/curves/gostr3410_2001_cryptopro_xcha.dart';
import 'package:pointycastle/ecc/curves/gostr3410_2001_cryptopro_xchb.dart';
import 'package:pointycastle/ecc/curves/prime192v1.dart';
import 'package:pointycastle/ecc/curves/prime192v2.dart';
import 'package:pointycastle/ecc/curves/prime192v3.dart';
import 'package:pointycastle/ecc/curves/prime239v1.dart';
import 'package:pointycastle/ecc/curves/prime239v2.dart';
import 'package:pointycastle/ecc/curves/prime239v3.dart';
import 'package:pointycastle/ecc/curves/prime256v1.dart';
import 'package:pointycastle/ecc/curves/secp112r1.dart';
import 'package:pointycastle/ecc/curves/secp112r2.dart';
import 'package:pointycastle/ecc/curves/secp128r1.dart';
import 'package:pointycastle/ecc/curves/secp128r2.dart';
import 'package:pointycastle/ecc/curves/secp160k1.dart';
import 'package:pointycastle/ecc/curves/secp160r1.dart';
import 'package:pointycastle/ecc/curves/secp160r2.dart';
import 'package:pointycastle/ecc/curves/secp192k1.dart';
import 'package:pointycastle/ecc/curves/secp192r1.dart';
import 'package:pointycastle/ecc/curves/secp224k1.dart';
import 'package:pointycastle/ecc/curves/secp224r1.dart';
import 'package:pointycastle/ecc/curves/secp256k1.dart';
import 'package:pointycastle/ecc/curves/secp256r1.dart';
import 'package:pointycastle/ecc/curves/secp384r1.dart';
import 'package:pointycastle/ecc/curves/secp521r1.dart';
import 'package:pointycastle/export.dart';
import 'package:pointycastle/key_derivators/hkdf.dart';
import 'package:pointycastle/key_derivators/pbkdf2.dart';
import 'package:pointycastle/key_derivators/scrypt.dart';
import 'package:pointycastle/key_generators/ec_key_generator.dart';
import 'package:pointycastle/key_generators/rsa_key_generator.dart';
import 'package:pointycastle/macs/cbc_block_cipher_mac.dart';
import 'package:pointycastle/macs/cmac.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/macs/poly1305.dart';
import 'package:pointycastle/padded_block_cipher/padded_block_cipher_impl.dart';
import 'package:pointycastle/paddings/iso7816d4.dart';
import 'package:pointycastle/paddings/pkcs7.dart';
import 'package:pointycastle/random/auto_seed_block_ctr_random.dart';
import 'package:pointycastle/random/block_ctr_random.dart';
import 'package:pointycastle/random/fortuna_random.dart';
import 'package:pointycastle/signers/ecdsa_signer.dart';
import 'package:pointycastle/signers/rsa_signer.dart';
import 'package:pointycastle/src/registry/registry.dart';
import 'package:pointycastle/stream/chacha20poly1305.dart';
import 'package:pointycastle/stream/chacha7539.dart';
import 'package:pointycastle/stream/ctr.dart';
import 'package:pointycastle/stream/salsa20.dart';
import 'package:pointycastle/stream/sic.dart';

void registerFactories(FactoryRegistry registry) {
  _registerAsymmetricCiphers(registry);
  _registerBlockCiphers(registry);
  _registerDigests(registry);
  _registerECCurves(registry);
  _registerKeyDerivators(registry);
  _registerKeyGenerators(registry);
  _registerMacs(registry);
  _registerPaddedBlockCiphers(registry);
  _registerPaddings(registry);
  _registerRandoms(registry);
  _registerSigners(registry);
  _registerStreamCiphers(registry);
}

void _registerAsymmetricCiphers(FactoryRegistry registry) {
  registry.register(OAEPEncoding.factoryConfig);
  registry.register(PKCS1Encoding.factoryConfig);
  registry.register(RSAEngine.factoryConfig);
}

void _registerBlockCiphers(FactoryRegistry registry) {
  registry.register(AESFastEngine.factoryConfig);

  // modes
  registry.register(CBCBlockCipher.factoryConfig);
  registry.register(CFBBlockCipher.factoryConfig);
  registry.register(CTRBlockCipher.factoryConfig);
  registry.register(ECBBlockCipher.factoryConfig);
  registry.register(GCTRBlockCipher.factoryConfig);
  registry.register(OFBBlockCipher.factoryConfig);
  registry.register(SICBlockCipher.factoryConfig);
  registry.register(GCMBlockCipher.factoryConfig);
}

void _registerDigests(FactoryRegistry registry) {
  registry.register(Blake2bDigest.factoryConfig);
  registry.register(MD2Digest.factoryConfig);
  registry.register(MD4Digest.factoryConfig);
  registry.register(MD5Digest.factoryConfig);
  registry.register(RIPEMD128Digest.factoryConfig);
  registry.register(RIPEMD160Digest.factoryConfig);
  registry.register(RIPEMD256Digest.factoryConfig);
  registry.register(RIPEMD320Digest.factoryConfig);
  registry.register(SHA1Digest.factoryConfig);
  registry.register(SHA3Digest.factoryConfig);
  registry.register(KeccakDigest.factoryConfig);
  registry.register(SHA224Digest.factoryConfig);
  registry.register(SHA256Digest.factoryConfig);
  registry.register(SHA384Digest.factoryConfig);
  registry.register(SHA512Digest.factoryConfig);
  registry.register(SHA512tDigest.factoryConfig);
  registry.register(TigerDigest.factoryConfig);
  registry.register(WhirlpoolDigest.factoryConfig);
  registry.register(SHAKEDigest.factoryConfig);
  registry.register(CSHAKEDigest.factoryConfig);
}

void _registerECCurves(FactoryRegistry registry) {
  registry.register(ECCurve_brainpoolp160r1.factoryConfig);
  registry.register(ECCurve_brainpoolp160t1.factoryConfig);
  registry.register(ECCurve_brainpoolp192r1.factoryConfig);
  registry.register(ECCurve_brainpoolp192t1.factoryConfig);
  registry.register(ECCurve_brainpoolp224r1.factoryConfig);
  registry.register(ECCurve_brainpoolp224t1.factoryConfig);
  registry.register(ECCurve_brainpoolp256r1.factoryConfig);
  registry.register(ECCurve_brainpoolp256t1.factoryConfig);
  registry.register(ECCurve_brainpoolp320r1.factoryConfig);
  registry.register(ECCurve_brainpoolp320t1.factoryConfig);
  registry.register(ECCurve_brainpoolp384r1.factoryConfig);
  registry.register(ECCurve_brainpoolp384t1.factoryConfig);
  registry.register(ECCurve_brainpoolp512r1.factoryConfig);
  registry.register(ECCurve_brainpoolp512t1.factoryConfig);
  registry.register(ECCurve_gostr3410_2001_cryptopro_a.factoryConfig);
  registry.register(ECCurve_gostr3410_2001_cryptopro_b.factoryConfig);
  registry.register(ECCurve_gostr3410_2001_cryptopro_c.factoryConfig);
  registry.register(ECCurve_gostr3410_2001_cryptopro_xcha.factoryConfig);
  registry.register(ECCurve_gostr3410_2001_cryptopro_xchb.factoryConfig);
  registry.register(ECCurve_prime192v1.factoryConfig);
  registry.register(ECCurve_prime192v2.factoryConfig);
  registry.register(ECCurve_prime192v3.factoryConfig);
  registry.register(ECCurve_prime239v1.factoryConfig);
  registry.register(ECCurve_prime239v2.factoryConfig);
  registry.register(ECCurve_prime239v3.factoryConfig);
  registry.register(ECCurve_prime256v1.factoryConfig);
  registry.register(ECCurve_secp112r1.factoryConfig);
  registry.register(ECCurve_secp112r2.factoryConfig);
  registry.register(ECCurve_secp128r1.factoryConfig);
  registry.register(ECCurve_secp128r2.factoryConfig);
  registry.register(ECCurve_secp160k1.factoryConfig);
  registry.register(ECCurve_secp160r1.factoryConfig);
  registry.register(ECCurve_secp160r2.factoryConfig);
  registry.register(ECCurve_secp192k1.factoryConfig);
  registry.register(ECCurve_secp192r1.factoryConfig);
  registry.register(ECCurve_secp224k1.factoryConfig);
  registry.register(ECCurve_secp224r1.factoryConfig);
  registry.register(ECCurve_secp256k1.factoryConfig);
  registry.register(ECCurve_secp256r1.factoryConfig);
  registry.register(ECCurve_secp384r1.factoryConfig);
  registry.register(ECCurve_secp521r1.factoryConfig);
}

void _registerKeyDerivators(FactoryRegistry registry) {
  registry.register(PBKDF2KeyDerivator.factoryConfig);
  registry.register(Scrypt.factoryConfig);
  registry.register(HKDFKeyDerivator.factoryConfig);
}

void _registerKeyGenerators(FactoryRegistry registry) {
  registry.register(ECKeyGenerator.factoryConfig);
  registry.register(RSAKeyGenerator.factoryConfig);
}

void _registerMacs(FactoryRegistry registry) {
  registry.register(HMac.factoryConfig);
  registry.register(CMac.factoryConfig);
  registry.register(CBCBlockCipherMac.factoryConfig);
  registry.register(Poly1305.factoryConfig);
}

void _registerPaddedBlockCiphers(FactoryRegistry registry) {
  registry.register(PaddedBlockCipherImpl.factoryConfig);
}

void _registerPaddings(FactoryRegistry registry) {
  registry.register(PKCS7Padding.factoryConfig);
  registry.register(ISO7816d4Padding.factoryConfig);
}

void _registerRandoms(FactoryRegistry registry) {
  registry.register(AutoSeedBlockCtrRandom.factoryConfig);
  registry.register(BlockCtrRandom.factoryConfig);
  registry.register(FortunaRandom.factoryConfig);
}

void _registerSigners(FactoryRegistry registry) {
  registry.register(ECDSASigner.factoryConfig);
  registry.register(PSSSigner.factoryConfig);
  registry.register(RSASigner.factoryConfig);
}

void _registerStreamCiphers(FactoryRegistry registry) {
  registry.register(CTRStreamCipher.factoryConfig);
  registry.register(Salsa20Engine.factoryConfig);
  registry.register(ChaCha20Engine.factoryConfig);
  registry.register(ChaCha7539Engine.factoryConfig);
  registry.register(ChaCha20Poly1305.factoryConfig);
  registry.register(SICStreamCipher.factoryConfig);
}
