// See file LICENSE for more information.

library impl.secure_random.dart_secure_random;

import 'dart:math';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/src/impl/secure_random_base.dart';
import 'package:pointycastle/src/registry/registry.dart';

/// An implementation of [SecureRandom] that uses darts built-in
/// [Random] to generate random bytes.
///
/// This implementation does not give any security guarantees, but
/// trusts the dart [Random] implementation to be cryptographically secure.
class DartSecureRandom extends SecureRandomBase implements SecureRandom {
  static const String _algorithmName = 'DartSecure';
  static final FactoryConfig factoryConfig = StaticFactoryConfig(
      SecureRandom, _algorithmName, () => DartSecureRandom());

  final Random _random;

  /// A newly created secure dart [Random] is used for byte generation.
  DartSecureRandom() : _random = Random.secure();

  /// Uses an insecure dart [Random]. This constructor should not be used
  /// in production!
  ///
  /// It is intended to be used during development when
  /// generating many cryptographically secure numbers takes
  /// to much time.
  DartSecureRandom.insecure([int? seed]) : _random = Random(seed);

  /// Uses an explicitly given dart [Random] for all operations.
  DartSecureRandom.withRandom(Random random) : _random = random;

  @override
  String get algorithmName => _algorithmName;

  @override
  int nextUint8() {
    return _random.nextInt(256);
  }

  /// The dart [Random] can not be seeded, so this is a no-op.
  @override
  void seed(CipherParameters params) {}
}
