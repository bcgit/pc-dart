// See file LICENSE for more information.

part of api;

abstract class SRPClient {
  BigInt calculateClientEvidenceMessage();
  BigInt calculateSecret(BigInt serverB);
  BigInt calculateSessionKey();
  BigInt generateClientCredentials(
      Uint8List salt, Uint8List identity, Uint8List password);
  bool verifyServerEvidenceMessage(BigInt serverM2);
}
