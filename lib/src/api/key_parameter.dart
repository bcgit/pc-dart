// See file LICENSE for more information.

part of pointycastle.api;

/// [CipherParameters] consisting of just a key of arbitrary length.
class KeyParameter extends CipherParameters {
  final Uint8List key;

  KeyParameter(this.key);
}
