import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/key_derivators/api.dart';
import 'package:pointycastle/src/impl/base_key_derivator.dart';
import 'package:pointycastle/src/registry/registry.dart';

class ConcatKDFDerivator extends BaseKeyDerivator {
  /// Intended for internal use.
  static final FactoryConfig factoryConfig =
      DynamicFactoryConfig.suffix(KeyDerivator, '/ConcatKDF', (_, Match match) {
    final digestName = match.group(1);
    final digest = Digest(digestName!);
    return () {
      return ConcatKDFDerivator(digest);
    };
  });

  final Digest _digest;
  late final ConcatKDFParameters _parameters;

  ConcatKDFDerivator(Digest this._digest);

  @override
  String get algorithmName => '${_digest.algorithmName}/ConcatKDF';

  @override
  int deriveKey(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    _digest.reset();

    var reps = _getReps(_parameters.keydatalen, _digest.digestSize * 8);
    for (var i = 1; i <= reps; i++) {
      int counterInt = i.toUnsigned(32);
      var counter = Uint8List(4);
      counter[0] = (counterInt >> 24) & 255;
      counter[1] = (counterInt >> 16) & 255;
      counter[2] = (counterInt >> 8) & 255;
      counter[3] = (counterInt) & 255;
      _digest.update(counter, 0, 4);
      _digest.update(_parameters.Z, 0, _parameters.Z.length);
      _digest.update(_parameters.otherInfo, 0, _parameters.otherInfo.length);
    }

    var output = Uint8List(_digest.byteLength);
    _digest.doFinal(output, 0);
    out.setAll(outOff, output.getRange(0, keySize));
    return keySize;
  }

  int _getReps(int keydatalen, int messagedigestlen) {
    return (keydatalen / messagedigestlen).ceil();
  }

  @override
  void init(CipherParameters params) {
    _parameters = params as ConcatKDFParameters;
  }

  @override
  int get keySize => (_parameters.keydatalen / 8).ceil();
}
