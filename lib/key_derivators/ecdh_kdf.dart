import 'dart:typed_data';

import 'package:pointycastle/export.dart';
import 'package:pointycastle/src/impl/base_key_derivator.dart';
import 'package:pointycastle/src/utils.dart';

import '../src/registry/registry.dart';

class ECDHKeyDerivator extends BaseKeyDerivator {
  late ECDHKDFParameters parameters;
  static final FactoryConfig factoryConfig =
      StaticFactoryConfig(KeyDerivator, 'ECDH', () => ECDHKeyDerivator());

  @override
  String get algorithmName => '/ECDH';

  @override
  int deriveKey(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    var ecdh = ECDHBasicAgreement()..init(parameters.privateKey);
    var ag = ecdh.calculateAgreement(parameters.publicKey);
    var key = encodeBigIntAsUnsigned(ag);
    out.setAll(outOff, key);
    return key.length;
  }

  @override
  void init(covariant ECDHKDFParameters params) {
    parameters = params;
  }

  @override
  int get keySize => (parameters.privateKey.parameters?.curve.fieldSize)!;
}
