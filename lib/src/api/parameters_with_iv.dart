// See file LICENSE for more information.

part of '../../api.dart';

/// [CipherParameters] consisting of an underlying [CipherParameters] (of type [UnderlyingParameters]) and an initialization
/// vector of arbitrary length.
class ParametersWithIV<UnderlyingParameters extends CipherParameters?>
    implements CipherParameters {
  final Uint8List iv;
  final UnderlyingParameters? parameters;

  ParametersWithIV(this.parameters, this.iv);
}
