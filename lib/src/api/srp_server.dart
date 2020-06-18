// See file LICENSE for more information.

part of api;

abstract class SRPServer {
  BigInt calculateSecret(BigInt clientA);
  BigInt calculateSessionKey();
  BigInt generateServerCredentials();
  BigInt calculateServerEvidenceMessage();
  bool verifyClientEvidenceMessage(BigInt clientM1);
}
