library impl.srp_server;

import 'package:pointycastle/srp/srp6_standard_groups.dart';
import 'package:pointycastle/srp/srp6_util.dart';
import "package:pointycastle/api.dart";

///FIXME rushed 1-1 port, respect private, add init, rewrite and document
/// Implements the server side SRP-6a protocol. Note that this class is stateful, and therefore NOT threadsafe.
/// This implementation of SRP is based on the optimized message sequence put forth by Thomas Wu in the paper
/// "SRP-6: Improvements and Refinements to the Secure Remote Password Protocol, 2002"
class SRP6Server implements SRPServer {
  BigInt N;
  BigInt g;
  BigInt v;

  SecureRandom random;
  Digest digest;

  BigInt A;

  BigInt b;
  BigInt B;

  BigInt u;
  BigInt S;
  BigInt M1;
  BigInt M2;
  BigInt Key;

  SRP6Server({SRP6GroupParameters group, this.v, this.digest, this.random}) {
    this.g = group.g;
    this.N = group.N;
  }

  /// Processes the client's credentials. If valid the shared secret is generated and returned.
  /// @param clientA The client's credentials
  /// @return A shared secret BigInt
  /// @throws CryptoException If client's credentials are invalid
  BigInt calculateSecret(BigInt clientA) {
    this.A = SRP6Util.validatePublicValue(N, clientA);
    this.u = SRP6Util.calculateU(digest, N, A, B);
    this.S = _calculateS();

    return S;
  }

  /// Computes the server evidence message M2 using the previously verified values.
  /// To be called after successfully verifying the client evidence message M1.
  /// @return M2: the server side generated evidence message
  /// @throws CryptoException
  BigInt calculateServerEvidenceMessage() {
// Verify pre-requirements
    if (this.A == null || this.M1 == null || this.S == null) {
      throw new Exception("Impossible to compute M2: " +
          "some data are missing from the previous operations (A,M1,S)");
    }

// Compute the server evidence message 'M2'
    this.M2 = SRP6Util.calculateM2(digest, N, A, M1, S);
    return M2;
  }

  /// Computes the final session key as a result of the SRP successful mutual authentication
  /// To be called after calculating the server evidence message M2.
  /// @return Key: the mutual authenticated symmetric session key
  /// @throws CryptoException
  BigInt calculateSessionKey() {
// Verify pre-requirements
    if (this.S == null || this.M1 == null || this.M2 == null) {
      throw new Exception("Impossible to compute Key: " +
          "some data are missing from the previous operations (S,M1,M2)");
    }
    this.Key = SRP6Util.calculateKey(digest, N, S);
    return Key;
  }

  /// Generates the server's credentials that are to be sent to the client.
  /// @return The server's public value to the client
  BigInt generateServerCredentials() {
    BigInt k = SRP6Util.calculateK(digest, N, g);
    this.b = selectPrivateValue();
    this.B = ((k * v + g.modPow(b, N)) % N);

    return B;
  }

  BigInt selectPrivateValue() {
    return SRP6Util.generatePrivateValue(digest, N, g, random);
  }

  /// Authenticates the received client evidence message M1 and saves it only if correct.
  /// To be called after calculating the secret S.
  /// @param clientM1 the client side generated evidence message
  /// @return A boolean indicating if the client message M1 was the expected one.
  /// @throws CryptoException
  bool verifyClientEvidenceMessage(BigInt clientM1) {
// Verify pre-requirements
    if (this.A == null || this.B == null || this.S == null) {
      throw new Exception("Impossible to compute and verify M1: " +
          "some data are missing from the previous operations (A,B,S)");
    }

// Compute the own client evidence message 'M1'
    BigInt computedM1 = SRP6Util.calculateM1(digest, N, A, B, S);
    if (computedM1.compareTo(clientM1) == 0) {
      this.M1 = clientM1;
      return true;
    }
    return false;
  }

  BigInt _calculateS() {
    return ((v.modPow(u, N) * A) % N).modPow(b, N);
  }
}
