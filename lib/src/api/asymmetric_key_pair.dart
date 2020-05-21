// See file LICENSE for more information.

part of pointycastle.api;

/// A pair of public and private asymmetric keys.
class AsymmetricKeyPair<B extends PublicKey, V extends PrivateKey> {
  final B publicKey;
  final V privateKey;

  AsymmetricKeyPair(this.publicKey, this.privateKey);
}
