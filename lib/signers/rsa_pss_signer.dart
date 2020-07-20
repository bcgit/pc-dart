// See file LICENSE for more information.

library impl.signer.rsa_signer;

import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/asymmetric/api.dart';
import 'package:pointycastle/asymmetric/pkcs1.dart';
import 'package:pointycastle/asymmetric/rsa.dart';
import 'package:pointycastle/src/registry/registry.dart';

class RSAPSSSigner implements Signer {
  /// Intended for internal use.
  static final FactoryConfig FACTORY_CONFIG =
      new DynamicFactoryConfig.suffix(Signer, '/RSA-PSS', (_, Match match) {
    final String digestName = match.group(1);
    final String digestIdentifierHex = _DIGEST_IDENTIFIER_HEXES[digestName];
    if (digestIdentifierHex == null) {
      throw new RegistryFactoryException(
          'RSA signing with digest $digestName is not supported');
    }
    return () => new RSAPSSSigner(new Digest(digestName), digestIdentifierHex);
  });

  static final Map<String, String> _DIGEST_IDENTIFIER_HEXES = {
    'MD2': '06082a864886f70d0202',
    'MD4': '06082a864886f70d0204',
    'MD5': '06082a864886f70d0205',
    'RIPEMD-128': '06052b24030202',
    'RIPEMD-160': '06052b24030201',
    'RIPEMD-256': '06052b24030203',
    'SHA-1': '06052b0e03021a',
    'SHA-224': '0609608648016503040204',
    'SHA-256': '0609608648016503040201',
    'SHA-384': '0609608648016503040202',
    'SHA-512': '0609608648016503040203'
  };

  final AsymmetricBlockCipher _rsa = PKCS1Encoding(RSAEngine());
  final Digest _digest;
  Uint8List _digestIdentifier; // DER encoded with trailing tag (06)+length byte
  bool _forSigning;

  RSAPSSSigner(this._digest, String digestIdentifierHex) {}

  String get algorithmName => '${_digest.algorithmName}/RSA-PSS';

  void reset() {
    _digest.reset();
    _rsa.reset();
  }

  void init(bool forSigning, CipherParameters params) {}

  RSASignature generateSignature(Uint8List message, {bool normalize = false}) {
    if (!_forSigning) {
      throw new StateError(
          'Signer was not initialised for signature generation');
    }
  }
}
