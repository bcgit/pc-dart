// See file LICENSE for more information.

library api.key_derivators;

import 'dart:typed_data';

import 'package:pointycastle/api.dart';

/// [CipherParameters] used by PBKDF2.
class Pbkdf2Parameters extends CipherParameters {
  final Uint8List salt;
  final int iterationCount;
  final int desiredKeyLength;

  Pbkdf2Parameters(this.salt, this.iterationCount, this.desiredKeyLength);
}

/// [CipherParameters] for the scrypt password based key derivation function.
class ScryptParameters implements CipherParameters {
  final int N;
  final int r;
  final int p;
  final int desiredKeyLength;
  final Uint8List salt;

  ScryptParameters(this.N, this.r, this.p, this.desiredKeyLength, this.salt);
}

/// Generates [CipherParameters] for HKDF key derivation function.
class HkdfParameters extends CipherParameters {
  final Uint8List ikm; // the input keying material or seed
  final int desiredKeyLength;
  final Uint8List
      salt; // the salt to use, may be null for a salt for hashLen zeros
  final Uint8List
      info; // the info to use, may be null for an info field of zero bytes
  final bool skipExtract;

  HkdfParameters._(this.ikm, this.desiredKeyLength,
      [this.salt, this.info, this.skipExtract = false]);

  factory HkdfParameters(ikm, desiredKeyLength,
      [salt, info, skipExtract = false]) {
    if (ikm == null) {
      throw ArgumentError('IKM (input keying material) should not be null');
    }

    if (salt == null || salt.length == 0) {
      salt = null;
    }

    return HkdfParameters._(
        ikm, desiredKeyLength, salt, info ?? Uint8List(0), skipExtract);
  }
}
