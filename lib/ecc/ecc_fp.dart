// See file LICENSE for more information.

library pointycastle.impl.ecc.ecc_fp;

import "dart:typed_data";

import "package:pointycastle/api.dart";
import "package:pointycastle/ecc/ecc_base.dart"
    hide ECFieldElementBase, ECPointBase, ECCurveBase;
import "package:pointycastle/ecc/ecc_base.dart" as ecc;
import "package:pointycastle/src/utils.dart" as utils;

/** return index of lowest 1-bit in x, x < 2^31 */
int _lbit(BigInt x) {
  // Implementation borrowed from bignum.BigIntegerDartvm.
  if (x == BigInt.zero) return -1;
  int r = 0;
  while ((x & new BigInt.from(0xffffffff)) == BigInt.zero) {
    x >>= 32;
    r += 32;
  }
  if ((x & new BigInt.from(0xffff)) == BigInt.zero) {
    x >>= 16;
    r += 16;
  }
  if ((x & new BigInt.from(0xff)) == BigInt.zero) {
    x >>= 8;
    r += 8;
  }
  if ((x & new BigInt.from(0xf)) == BigInt.zero) {
    x >>= 4;
    r += 4;
  }
  if ((x & new BigInt.from(3)) == BigInt.zero) {
    x >>= 2;
    r += 2;
  }
  if ((x & BigInt.one) == BigInt.zero) ++r;
  return r;
}

bool _testBit(BigInt i, int n) {
  return i & (BigInt.one << n) != BigInt.zero;
}

class ECFieldElement extends ecc.ECFieldElementBase {
  final BigInt q;
  final BigInt x;

  ECFieldElement(this.q, this.x) {
    if (x >= q) {
      throw new ArgumentError("Value x must be smaller than q");
    }
  }

  String get fieldName => "Fp";
  int get fieldSize => q.bitLength;

  BigInt toBigInteger() => x;

  ECFieldElement operator +(ECFieldElement b) =>
      new ECFieldElement(q, (x + b.toBigInteger()) % q);
  ECFieldElement operator -(ECFieldElement b) =>
      new ECFieldElement(q, (x - b.toBigInteger()) % q);
  ECFieldElement operator *(ECFieldElement b) =>
      new ECFieldElement(q, (x * b.toBigInteger()) % q);
  ECFieldElement operator /(ECFieldElement b) =>
      new ECFieldElement(q, (x * b.toBigInteger().modInverse(q)) % q);

  ECFieldElement operator -() => new ECFieldElement(q, -x % q);

  ECFieldElement invert() => new ECFieldElement(q, x.modInverse(q));
  ECFieldElement square() => new ECFieldElement(q, x.modPow(BigInt.two, q));

  // D.1.4 91
  /**
   * return a sqrt root - the routine verifies that the calculation
   * returns the right value - if none exists it returns null.
   */
  ECFieldElement sqrt() {
    if (!_testBit(q, 0)) {
      throw new UnimplementedError("Not implemented yet");
    }

    // p % 4 == 3
    if (_testBit(q, 1)) {
      // z = g^(u+1) + p, p = 4u + 3
      var z = new ECFieldElement(q, x.modPow((q >> 2) + BigInt.one, q));
      return z.square() == this ? z : null;
    }

    // p % 4 == 1
    var qMinusOne = q - BigInt.one;

    var legendreExponent = qMinusOne >> 1;
    if (x.modPow(legendreExponent, q) != BigInt.one) {
      return null;
    }

    var u = qMinusOne >> 2;
    var k = (u << 1) + BigInt.one;

    var Q = x;
    var fourQ = (Q >> 2) % q;

    var U, V;
    var rand = new SecureRandom();
    do {
      BigInt P;
      do {
        P = rand.nextBigInteger(q.bitLength);
      } while ((P >= q) ||
          (((P * P) - fourQ).modPow(legendreExponent, q) != qMinusOne));

      List<BigInt> result = _lucasSequence(q, P, Q, k);
      U = result[0];
      V = result[1];

      if (((V * V) % q) == fourQ) {
        // Integer division by 2, mod q
        if (_testBit(V, 0)) {
          V = V + q;
        }

        V = (V >> 1);

        //assert V.multiply(V).mod(q).equals(x);

        return new ECFieldElement(q, V);
      }
    } while ((U == BigInt.one) || (U == qMinusOne));

    return null;
  }

  List<BigInt> _lucasSequence(BigInt p, BigInt P, BigInt Q, BigInt k) {
    var n = k.bitLength;
    var s = _lbit(k);

    BigInt Uh = BigInt.one;
    BigInt Vl = BigInt.two;
    BigInt Vh = P;
    BigInt Ql = BigInt.one;
    BigInt Qh = BigInt.one;

    for (var j = n - 1; j >= (s + 1); j--) {
      Ql = (Ql * Qh) % p;

      if (_testBit(k, j)) {
        Qh = (Ql * Q) % p;
        Uh = (Uh * Vh) % p;
        Vl = ((Vh * Vl) - (P * Ql)) % p;
        Vh = ((Vh * Vh) - (Qh << 1)) % p;
      } else {
        Qh = Ql;
        Uh = ((Uh * Vl) - Ql) % p;
        Vh = ((Vh * Vl) - (P * Ql)) % p;
        Vl = ((Vl * Vl) - (Ql << 1)) % p;
      }
    }

    Ql = (Ql * Qh) % p;
    Qh = (Ql * Q) % p;
    Uh = ((Uh * Vl) - Ql) % p;
    Vl = ((Vh * Vl) - (P * Ql)) % p;
    Ql = (Ql * Qh) % p;

    for (var j = 1; j <= s; j++) {
      Uh = (Uh * Vl) % p;
      Vl = ((Vl * Vl) - (Ql << 1)) % p;
      Ql = (Ql * Ql) % p;
    }

    return [Uh, Vl];
  }

  bool operator ==(other) {
    if (other is ECFieldElement) {
      return (q == other.q) && (x == other.x);
    }
    return false;
  }

  int get hashCode => q.hashCode ^ x.hashCode;
}

/// Elliptic curve points over Fp
class ECPoint extends ecc.ECPointBase {
  /**
   * Create a point that encodes with or without point compresion.
   *
   * @param curve the curve to use
   * @param x affine x co-ordinate
   * @param y affine y co-ordinate
   * @param withCompression if true encode with point compression
   */
  ECPoint(ECCurve curve, ECFieldElement x, ECFieldElement y,
      [bool withCompression = false])
      : super(curve, x, y, withCompression, _WNafMultiplier) {
    if ((x != null && y == null) || (x == null && y != null)) {
      throw new ArgumentError("Exactly one of the field elements is null");
    }
  }

  /// return the field element encoded with point compression. (S 4.3.6)
  Uint8List getEncoded([bool compressed = true]) {
    if (isInfinity) {
      return new Uint8List.fromList([1]);
    }

    var qLength = x.byteLength;
    if (compressed) {
      int PC;

      if (_testBit(y.toBigInteger(), 0)) {
        PC = 0x03;
      } else {
        PC = 0x02;
      }

      Uint8List X = _x9IntegerToBytes(x.toBigInteger(), qLength);
      Uint8List PO = new Uint8List(X.length + 1);

      PO[0] = PC.toInt();
      PO.setAll(1, X);

      return PO;
    } else {
      Uint8List X = _x9IntegerToBytes(x.toBigInteger(), qLength);
      Uint8List Y = _x9IntegerToBytes(y.toBigInteger(), qLength);
      Uint8List PO = new Uint8List(X.length + Y.length + 1);

      PO[0] = 0x04;
      PO.setAll(1, X);
      PO.setAll(X.length + 1, Y);

      return PO;
    }
  }

  // B.3 pg 62
  ECPoint operator +(ECPoint b) {
    if (isInfinity) {
      return b;
    }

    if (b.isInfinity) {
      return this;
    }

    // Check if b = this or b = -this
    if (x == b.x) {
      if (y == b.y) {
        // this = b, i.e. this must be doubled
        return twice();
      }

      // this = -b, i.e. the result is the point at infinity
      return curve.infinity;
    }

    var gamma = (b.y - y) / (b.x - x);

    var x3 = (gamma.square() - x) - b.x;
    var y3 = (gamma * (x - x3)) - y;

    return new ECPoint(curve, x3, y3, isCompressed);
  }

  // B.3 pg 62
  ECPoint twice() {
    if (isInfinity) {
      // Twice identity element (point at infinity) is identity
      return this;
    }

    if (y.toBigInteger() == 0) {
      // if y1 == 0, then (x1, y1) == (x1, -y1)
      // and hence this = -this and thus 2(x1, y1) == infinity
      return this.curve.infinity;
    }

    var TWO = curve.fromBigInteger(BigInt.two);
    var THREE = curve.fromBigInteger(new BigInt.from(3));
    var gamma = ((x.square() * THREE) + curve.a) / (y * TWO);

    var x3 = gamma.square() - (x * TWO);
    var y3 = (gamma * (x - x3)) - y;

    return new ECPoint(curve, x3, y3, isCompressed);
  }

  // D.3.2 pg 102 (see Note:)
  ECPoint operator -(ECPoint b) {
    if (b.isInfinity) {
      return this;
    }

    // Add -b
    return this + (-b);
  }

  ECPoint operator -() {
    return new ECPoint(curve, x, -y, isCompressed);
  }
}

/// Elliptic curve over Fp
class ECCurve extends ecc.ECCurveBase {
  final BigInt q;
  ECPoint _infinity;

  ECCurve(this.q, BigInt a, BigInt b) : super(a, b) {
    _infinity = new ECPoint(this, null, null);
  }

  int get fieldSize => q.bitLength;
  ECPoint get infinity => _infinity;

  ECFieldElement fromBigInteger(BigInt x) => new ECFieldElement(this.q, x);
  ECPoint createPoint(BigInt x, BigInt y, [bool withCompression = false]) =>
      new ECPoint(this, fromBigInteger(x), fromBigInteger(y), withCompression);

  ECPoint decompressPoint(int yTilde, BigInt X1) {
    var x = fromBigInteger(X1);
    var alpha = (x * ((x * x) + a)) + b;
    ECFieldElement beta = alpha.sqrt();

    //
    // if we can't find a sqrt we haven't got a point on the
    // curve - run!
    //
    if (beta == null) {
      throw new ArgumentError("Invalid point compression");
    }

    var betaValue = beta.toBigInteger();
    var bit0 = _testBit(betaValue, 0) ? 1 : 0;

    if (bit0 != yTilde) {
      // Use the other root
      beta = fromBigInteger(q - betaValue);
    }

    return new ECPoint(this, x, beta, true);
  }

  bool operator ==(other) {
    if (other is ECCurve) {
      return q == other.q && a == other.a && b == other.b;
    }
    return false;
  }

  int get hashCode => a.hashCode ^ b.hashCode ^ q.hashCode;
}

/**
 * Class holding precomputation data for the WNAF (Window Non-Adjacent Form)
 * algorithm.
 */
class _WNafPreCompInfo implements PreCompInfo {
  /// Array holding the precomputed [ECPoint]s used for the Window NAF multiplication.
  List<ECPoint> preComp;

  /// Holds an [ECPoint] representing twice(this). Used for the Window NAF multiplication.
  ECPoint twiceP;
}

/**
 * Function implementing the WNAF (Window Non-Adjacent Form) multiplication algorithm. Multiplies [p]] by an integer [k] using
 * the Window NAF method.
 */
ecc.ECPointBase _WNafMultiplier(
    ecc.ECPointBase p, BigInt k, PreCompInfo preCompInfo) {
  // Ignore empty PreCompInfo or PreCompInfo of incorrect type
  _WNafPreCompInfo wnafPreCompInfo = preCompInfo;
  if ((preCompInfo == null) && (preCompInfo is! _WNafPreCompInfo)) {
    wnafPreCompInfo = new _WNafPreCompInfo();
  }

  // floor(log2(k))
  var m = k.bitLength;

  // width of the Window NAF
  var width;

  // Required length of precomputation array
  var reqPreCompLen;

  // Determine optimal width and corresponding length of precomputation
  // array based on literature values
  if (m < 13) {
    width = 2;
    reqPreCompLen = 1;
  } else {
    if (m < 41) {
      width = 3;
      reqPreCompLen = 2;
    } else {
      if (m < 121) {
        width = 4;
        reqPreCompLen = 4;
      } else {
        if (m < 337) {
          width = 5;
          reqPreCompLen = 8;
        } else {
          if (m < 897) {
            width = 6;
            reqPreCompLen = 16;
          } else {
            if (m < 2305) {
              width = 7;
              reqPreCompLen = 32;
            } else {
              width = 8;
              reqPreCompLen = 127;
            }
          }
        }
      }
    }
  }

  // The length of the precomputation array
  var preCompLen = 1;

  var preComp = wnafPreCompInfo.preComp;
  var twiceP = wnafPreCompInfo.twiceP;

  // Check if the precomputed ECPoints already exist
  if (preComp == null) {
    // Precomputation must be performed from scratch, create an empty
    // precomputation array of desired length
    preComp = new List<ECPoint>.filled(1, p);
  } else {
    // Take the already precomputed ECPoints to start with
    preCompLen = preComp.length;
  }

  if (twiceP == null) {
    // Compute twice(p)
    twiceP = p.twice();
  }

  if (preCompLen < reqPreCompLen) {
    // Precomputation array must be made bigger, copy existing preComp
    // array into the larger new preComp array
    List<ECPoint> oldPreComp = preComp;
    preComp = new List<ECPoint>(reqPreCompLen);
    preComp.setAll(0, oldPreComp);

    for (int i = preCompLen; i < reqPreCompLen; i++) {
      // Compute the new ECPoints for the precomputation array.
      // The values 1, 3, 5, ..., 2^(width-1)-1 times p are
      // computed
      preComp[i] = twiceP + (preComp[i - 1]);
    }
  }

  // Compute the Window NAF of the desired width
  var wnaf = _windowNaf(width, k);
  var l = wnaf.length;

  // Apply the Window NAF to p using the precomputed ECPoint values.
  var q = p.curve.infinity;
  for (int i = l - 1; i >= 0; i--) {
    q = q.twice();

    if (wnaf[i] != 0) {
      if (wnaf[i] > 0) {
        q += preComp[(wnaf[i] - 1) ~/ 2];
      } else {
        // wnaf[i] < 0
        q -= preComp[(-wnaf[i] - 1) ~/ 2];
      }
    }
  }

  // Set PreCompInfo in ECPoint, such that it is available for next
  // multiplication.
  wnafPreCompInfo.preComp = preComp;
  wnafPreCompInfo.twiceP = twiceP;
  p.preCompInfo = wnafPreCompInfo;
  return q;
}

/**
 * Computes the Window NAF (non-adjacent Form) of an integer.
 * @param width The width <code>w</code> of the Window NAF. The width is
 * defined as the minimal number <code>w</code>, such that for any
 * <code>w</code> consecutive digits in the resulting representation, at
 * most one is non-zero.
 * @param k The integer of which the Window NAF is computed.
 * @return The Window NAF of the given width, such that the following holds:
 * <code>k = &sum;<sub>i=0</sub><sup>l-1</sup> k<sub>i</sub>2<sup>i</sup>
 * </code>, where the <code>k<sub>i</sub></code> denote the elements of the
 * returned <code>byte[]</code>.
 */
List<int> _windowNaf(int width, BigInt k) {
  // The window NAF is at most 1 element longer than the binary
  // representation of the integer k. byte can be used instead of short or
  // int unless the window width is larger than 8. For larger width use
  // short or int. However, a width of more than 8 is not efficient for
  // m = log2(q) smaller than 2305 Bits. Note: Values for m larger than
  // 1000 Bits are currently not used in practice.
  List<int> wnaf = new List<int>(k.bitLength + 1);

  // 2^width as short and BigInt
  int pow2wB = (1 << width);
  BigInt pow2wBI = new BigInt.from(pow2wB);

  int i = 0;

  // The actual length of the WNAF
  int length = 0;

  // while k >= 1
  while (k.sign > 0) {
    // if k is odd
    if (_testBit(k, 0)) {
      // k mod 2^width
      BigInt remainder = k % pow2wBI;

      // if remainder > 2^(width - 1) - 1
      if (_testBit(remainder, width - 1)) {
        wnaf[i] = remainder.toInt() - pow2wB;
      } else {
        wnaf[i] = remainder.toInt();
      }

      // convert to "Java byte"
      wnaf[i] %= 0x100;
      if ((wnaf[i] & 0x80) != 0) {
        wnaf[i] = wnaf[i] - 256;
      }

      // wnaf[i] is now in [-2^(width-1), 2^(width-1)-1]

      k = k - new BigInt.from(wnaf[i]);
      length = i;
    } else {
      wnaf[i] = 0;
    }

    // k = k/2
    k = k >> 1;
    i++;
  }

  length++;

  // Reduce the WNAF array to its actual length
  List<int> wnafShort = new List<int>(length);
  wnafShort.setAll(0, wnaf.sublist(0, length));
  return wnafShort;
}

Uint8List _x9IntegerToBytes(BigInt s, int qLength) {
  Uint8List bytes = new Uint8List.fromList(utils.encodeBigInt(s));

  if (qLength < bytes.length) {
    return bytes.sublist(bytes.length - qLength);
  } else if (qLength > bytes.length) {
    return new Uint8List(qLength)..setAll(qLength - bytes.length, bytes);
  }

  return bytes;
}
