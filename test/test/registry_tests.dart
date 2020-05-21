// See file LICENSE for more information.

library pointycastle.test.test.registry_tests;

import "package:pointycastle/pointycastle.dart";

import "package:test/test.dart";
import "package:matcher/matcher.dart";

void testAsymmetricBlockCipher(String algorithmName) {
  var cipher = new AsymmetricBlockCipher(algorithmName);
  expect(cipher, new isInstanceOf<AsymmetricBlockCipher>());
  expect(cipher.algorithmName, algorithmName);
}

void testBlockCipher(String algorithmName) {
  var cipher = new BlockCipher(algorithmName);
  expect(cipher, new isInstanceOf<BlockCipher>());
  expect(cipher.algorithmName, algorithmName);
}

void testDigest(String algorithmName) {
  var digest = new Digest(algorithmName);
  expect(digest, new isInstanceOf<Digest>());
  expect(digest.algorithmName, algorithmName);
}

void testECDomainParameters(String domainName) {
  var domain = new ECDomainParameters(domainName);
  expect(domain, new isInstanceOf<ECDomainParameters>());
  expect(domain.domainName, domainName);
}

void testKeyDerivator(String algorithmName) {
  var kf = new KeyDerivator(algorithmName);
  expect(kf, new isInstanceOf<KeyDerivator>());
  expect(kf.algorithmName, algorithmName);
}

void testKeyGenerator(String algorithmName) {
  var kg = new KeyGenerator(algorithmName);
  expect(kg, new isInstanceOf<KeyGenerator>());
  expect(kg.algorithmName, algorithmName);
}

void testMac(String algorithmName) {
  var mac = new Mac(algorithmName);
  expect(mac, new isInstanceOf<Mac>());
  expect(mac.algorithmName, algorithmName);
}

void testPaddedBlockCipher(String algorithmName) {
  var parts = algorithmName.split("/");

  var pbc = new PaddedBlockCipher(algorithmName);
  expect(pbc, new isInstanceOf<PaddedBlockCipher>());
  expect(pbc.algorithmName, algorithmName);

  var padding = pbc.padding;
  expect(padding, new isInstanceOf<Padding>());
  expect(padding.algorithmName, equals(parts[2]));

  var cbc = pbc.cipher;
  expect(cbc, new isInstanceOf<BlockCipher>());
  expect(cbc.algorithmName, equals("${parts[0]}/${parts[1]}"));
}

void testPadding(String algorithmName) {
  var padding = new Padding(algorithmName);
  expect(padding, new isInstanceOf<Padding>());
  expect(padding.algorithmName, algorithmName);
}

void testSecureRandom(String algorithmName) {
  var rnd = new SecureRandom(algorithmName);
  expect(rnd, new isInstanceOf<SecureRandom>());
  expect(rnd.algorithmName, algorithmName);
}

void testSigner(String algorithmName) {
  var signer = new Signer(algorithmName);
  expect(signer, new isInstanceOf<Signer>());
  expect(signer.algorithmName, algorithmName);
}

void testStreamCipher(String algorithmName) {
  var cipher = new StreamCipher(algorithmName);
  expect(cipher, new isInstanceOf<StreamCipher>());
  expect(cipher.algorithmName, algorithmName);
}
