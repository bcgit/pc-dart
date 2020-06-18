library impl.srp_client;

import 'dart:typed_data';

import 'package:pointycastle/srp/srp6_standard_groups.dart';
import 'package:pointycastle/srp/srp6_util.dart';
import "package:pointycastle/api.dart";

class SRP6Client implements SRPClient {
  BigInt N;
  BigInt g;

  BigInt a;
  BigInt A;

  BigInt B;

  BigInt x;
  BigInt u;
  BigInt S;

  BigInt M1;
  BigInt M2;
  BigInt Key;

  Digest digest = Digest("SHA-256");
  SecureRandom random = SecureRandom("AES/CTR/AUTO-SEED-PRNG");
  SRP6GroupParameters group = SRP6StandardGroups.rfc5054_2048;

  SRP6Client({this.group, this.digest, this.random}) {
    g = group.g;
    N = group.N;
  }

  ///Computes the client evidence message M1 using the previously received values.
  ///To be called after calculating the secret S.
  ///returns M1: the client side generated evidence message
  ///throws Exception
  BigInt calculateClientEvidenceMessage() {
    // Verify pre-requirements
    if (A == null || B == null || S == null) {
      throw new Exception("Impossible to compute M1: " +
          "some data are missing from the previous operations (A,B,S)");
    }
    // compute the client evidence message 'M1'
    this.M1 = SRP6Util.calculateM1(digest, N, A, B, S);
    return M1;
  }

  ///S = (B - kg^x) ^ (a + ux)
  BigInt calculateS() {
    BigInt k = SRP6Util.calculateK(digest, N, g);
    BigInt exp = (u * x) + a;
    BigInt tmp = g.modPow(x, N) * (k % N);
    //FIXME add N to B for negative case?
    return (B - (tmp % (N))).modPow(exp, N);
  }

  ///
  ///Generates the secret S given the server's credentials
  ///@param serverB The server's credentials
  ///@return Client's verification message for the server
  ///@throws Exception If server's credentials are invalid
  ///
  BigInt calculateSecret(BigInt serverB) {
    B = SRP6Util.validatePublicValue(N, serverB);
    u = SRP6Util.calculateU(digest, N, A, B);
    S = calculateS();
    return S;
  }

  /// Computes the final session key as a result of the SRP successful mutual authentication
  /// To be called after verifying the server evidence message M2.
  /// returns Key: the mutually authenticated symmetric session key
  /// throws Exception
  BigInt calculateSessionKey() {
// Verify pre-requirements (here we enforce a previous calculation of M1 and M2)
    if (S == null || M1 == null || M2 == null) {
      throw new Exception("Impossible to compute Key: " +
          "some data are missing from the previous operations (S,M1,M2)");
    }
    this.Key = SRP6Util.calculateKey(digest, N, S);
    return Key;
  }

  BigInt generateClientCredentials(
      Uint8List salt, Uint8List identity, Uint8List password) {
    x = SRP6Util.calculateX(digest, N, salt, identity, password);
    a = selectPrivateValue();
    A = g.modPow(a, N);
    return A;
  }

  BigInt selectPrivateValue() {
    return SRP6Util.generatePrivateValue(digest, N, g, random);
  }

  /// Authenticates the server evidence message M2 received and saves it only if correct.
  /// [serverM2] the server side generated evidence message
  /// return A boolean indicating if the server message M2 was the expected one.
  /// throws Exception
  bool verifyServerEvidenceMessage(BigInt serverM2) {
    // Verify pre-requirements
    if (A == null || M1 == null || S == null) {
      throw new Exception("Impossible to compute and verify M2: " +
          "some data are missing from the previous operations (A,M1,S)");
    }
    // Compute the own server evidence message 'M2'
    BigInt computedM2 = SRP6Util.calculateM2(digest, N, A, M1, S);
    if (computedM2.compareTo(serverM2) == 0) {
      this.M2 = serverM2;
      return true;
    }
    return false;
  }
}
