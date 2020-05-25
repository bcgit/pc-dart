// See file LICENSE for more information.

library pointycastle.test.test.signer_tests;

import "package:test/test.dart";
import "package:pointycastle/pointycastle.dart";

import "./src/helpers.dart";

void runSignerTests(Signer signer, CipherParameters signParams(),
    CipherParameters verifyParams(), List messageSignaturePairs, {bool normalize = false}) {
  group("${signer.algorithmName}:", () {
    group("generateSignature:", () {
      for (var i = 0; i < messageSignaturePairs.length; i += 2) {
        var message = messageSignaturePairs[i];
        var signature = messageSignaturePairs[i + 1];

        test(
            "${formatAsTruncated(message)}",
            () => _runGenerateSignatureTest(
                signer, signParams, message, signature, normalize: normalize));
      }
    });

    group("verifySignature:", () {
      for (var i = 0; i < messageSignaturePairs.length; i += 2) {
        var message = messageSignaturePairs[i];
        var signature = messageSignaturePairs[i + 1];

        test(
            "${formatAsTruncated(message)}",
            () => _runVerifySignatureTest(
                signer, verifyParams, message, signature));
      }
    });
  });
}

void _runGenerateSignatureTest(Signer signer, CipherParameters params(),
    String message, Signature expectedSignature, {bool normalize = false}) {
  signer.reset();
  signer.init(true, params());

  var signature = signer.generateSignature(createUint8ListFromString(message), normalize: normalize);

  expect(signature, expectedSignature);
}

void _runVerifySignatureTest(Signer signer, CipherParameters params(),
    String message, Signature signature) {
  signer.reset();
  signer.init(false, params());

  var ok =
      signer.verifySignature(createUint8ListFromString(message), signature);

  expect(ok, true);
}
