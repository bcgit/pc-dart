// See file LICENSE for more information.

library pointycastle.src.impl.random.secure_random_base;

import "dart:typed_data";

import "package:pointycastle/api.dart";
import "package:pointycastle/src/ufixnum.dart";
import "package:pointycastle/src/utils.dart" as utils;

/**
 * An utility base implementation of [SecureRandom] so that only [nextUint8] method needs to be
 * implemented.
 */
abstract class SecureRandomBase implements SecureRandom {
  int nextUint16() {
    var b0 = nextUint8();
    var b1 = nextUint8();
    return clip16((b1 << 8) | b0);
  }

  int nextUint32() {
    var b0 = nextUint8();
    var b1 = nextUint8();
    var b2 = nextUint8();
    var b3 = nextUint8();
    return clip32((b3 << 24) | (b2 << 16) | (b1 << 8) | b0);
  }

  BigInt nextBigInteger(int bitLength) {
    return utils.decodeBigInt(_randomBits(bitLength));
  }

  Uint8List nextBytes(int count) {
    var bytes = new Uint8List(count);
    for (var i = 0; i < count; i++) {
      bytes[i] = nextUint8();
    }
    return bytes;
  }

  List<int> _randomBits(int numBits) {
    if (numBits < 0) {
      throw new ArgumentError("numBits must be non-negative");
    }

    var numBytes = (numBits + 7) ~/ 8; // avoid overflow
    var randomBits = new Uint8List(numBytes);

    // Generate random bytes and mask out any excess bits
    if (numBytes > 0) {
      for (var i = 0; i < numBytes; i++) {
        randomBits[i] = nextUint8();
      }
      int excessBits = 8 * numBytes - numBits;
      randomBits[0] &= (1 << (8 - excessBits)) - 1;
    }
    return randomBits;
  }
}
