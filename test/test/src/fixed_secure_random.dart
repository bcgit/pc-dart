// See file LICENSE for more information.

library pointycastle.impl.secure_random.test.src.fixed_secure_random;

import "package:pointycastle/api.dart";
import "package:pointycastle/src/impl/secure_random_base.dart";
import "package:pointycastle/src/registry/registry.dart";

/// An implementation of [SecureRandom] that return fixed values.
///
/// The source of the fixed values is set using the [seed] method. If it is not
/// set, or was set with no data, zero is always returned as the random values.
///
/// If the end of the source is reached, it wraps around to the beginning of the
/// source.
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
  // ignore: non_constant_identifier_names
  static final FactoryConfig FACTORY_CONFIG =
      StaticFactoryConfig(SecureRandom, 'Fixed', () => FixedSecureRandom());

  var _next = 0;
  // ignore: prefer_typing_uninitialized_variables
  var _values;

  @override
  String get algorithmName => 'Fixed';

  /// Set the fixed values to use and reset to the beginning of it.

  @override
  void seed(covariant KeyParameter params) {
    _values = params.key; // set the values to use (could be null or empty)
    _next = 0; // reset to the beginning of the values
  }

  @override
  int nextUint8() {
    if (_values != null && _values.isNotEmpty as bool) {
      if (_next >= (_values.length as int)) {
        _next = 0; // reset to beginning of the array
      }
      return _values[_next++] as int;
    } else {
      return 0; // value when not set with any values
    }
  }
}
