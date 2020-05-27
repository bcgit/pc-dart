// See file LICENSE for more information.

library pointycastle.impl.secure_random.test.src.fixed_secure_random;

import "package:pointycastle/api.dart";
import "package:pointycastle/src/impl/secure_random_base.dart";
import "package:pointycastle/src/registry/registry.dart";

/// An implementation of [SecureRandom] that return fixed values.
///
/// The source of the fixed values is set using the [seed] method.
///
/// Will throw StateError when end of entropy source is reached or if
/// no values are set.
///
/// For example,
///
///     Uint8List s = ...
///
///     FixedSecureRandom sr = FixedSecureRandom();
///     sr.seed(KeyParameter(s);
///
///     final a = sr.nextUint8();
///     final b = sr.nextUint8();
///     final c = sr.nextUint8();
///     assert (a == s[0] && b = s[1] && c == s[2]);

class FixedSecureRandom extends SecureRandomBase {
  static final FactoryConfig FACTORY_CONFIG =
      new StaticFactoryConfig(SecureRandom, "Fixed", () => FixedSecureRandom());

  var _next = 0;
  var _values;

  String get algorithmName => "Fixed";

  /// Set the fixed values to use and reset to the beginning of it.

  void seed(covariant KeyParameter params) {
    _values = params.key; // set the values to use (could be null or empty)
    _next = 0; // reset to the beginning of the values
  }

  int nextUint8() {
    if (_values != null && _values.isNotEmpty) {
      if (_next >= _values.length) {
        throw StateError("fixed secure random unexpectedly exhausted");
      }
      return _values[_next++];
    } else {
      throw StateError("fixed secure random has no values");
    }
  }
}
