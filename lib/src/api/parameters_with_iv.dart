// See file LICENSE for more information.

part of api;

//TODO rename
/**
 * [CipherParameters] consisting of an underlying [CipherParameters] (of type [UnderlyingParameters]) and an initialization
 * vector of arbitrary length.
 */
class ParametersWithIV<UnderlyingParameters extends CipherParameters>
    implements CipherParameters {
  final Uint8List iv;
  final UnderlyingParameters parameters;

  ParametersWithIV(this.parameters, this.iv);
}

/// Adds an additional initial counter for [ChaCha20Engine].
class ParametersWithIVAndInitialCounter<
        UnderlyingParameters extends CipherParameters>
    extends ParametersWithIV<UnderlyingParameters> {
  final int initialCounter;

  ParametersWithIVAndInitialCounter(
      UnderlyingParameters parameters, Uint8List iv, this.initialCounter)
      : super(parameters, iv);
}
