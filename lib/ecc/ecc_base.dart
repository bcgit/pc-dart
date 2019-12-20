// See file LICENSE for more information.

library pointycastle.impl.ecc.ecc_base;
//TODO I think this stuff might be moved to src/impl

import "dart:typed_data";

import "package:pointycastle/ecc/api.dart";
import "package:pointycastle/src/utils.dart" as utils;

/// Implementation of [ECDomainParameters]
class ECDomainParametersImpl implements ECDomainParameters {
  final String domainName;
  final ECCurve curve;
  final List<int> seed;
  final ECPoint G;
  final BigInt n;
  BigInt _h;

  ECDomainParametersImpl(this.domainName, this.curve, this.G, this.n,
      [this._h = null, this.seed = null]) {
    if (_h == null) {
      _h = BigInt.one;
    }
  }

  BigInt get h => _h;
}

/// Base implementation for [ECFieldElement]
abstract class ECFieldElementBase implements ECFieldElement {
  BigInt toBigInteger();
  String get fieldName;
  int get fieldSize;
  int get byteLength => ((fieldSize + 7) ~/ 8);

  ECFieldElementBase operator +(covariant ECFieldElementBase b);
  ECFieldElementBase operator -(covariant ECFieldElementBase b);
  ECFieldElementBase operator *(covariant ECFieldElementBase b);
  ECFieldElementBase operator /(covariant ECFieldElementBase b);

  ECFieldElementBase operator -();

  ECFieldElementBase invert();
  ECFieldElementBase square();
  ECFieldElementBase sqrt();

  String toString() => toBigInteger().toString();
}

/// Base implementation for [ECPoint]
abstract class ECPointBase implements ECPoint {
  final ECCurveBase curve;
  final ECFieldElementBase x;
  final ECFieldElementBase y;
  final bool isCompressed;
  final ECMultiplier _multiplier;

  PreCompInfo _preCompInfo;

  ECPointBase(this.curve, this.x, this.y, this.isCompressed,
      [this._multiplier = _FpNafMultiplier]);

  bool get isInfinity => (x == null && y == null);

  void set preCompInfo(PreCompInfo preCompInfo) {
    _preCompInfo = preCompInfo;
  }

  bool operator ==(other) {
    if (other is ECPointBase) {
      if (isInfinity) {
        return other.isInfinity;
      }
      return x == other.x && y == other.y;
    }
    return false;
  }

  String toString() => "($x,$y)";

  int get hashCode {
    if (isInfinity) {
      return 0;
    }
    return x.hashCode ^ y.hashCode;
  }

  Uint8List getEncoded([bool compressed = true]);

  ECPointBase operator +(covariant ECPointBase b);
  ECPointBase operator -(covariant ECPointBase b);
  ECPointBase operator -();

  ECPointBase twice();

  /**
   * Multiplies this <code>ECPoint</code> by the given number.
   * @param k The multiplicator.
   * @return <code>k * this</code>.
   */
  ECPointBase operator *(BigInt k) {
    if (k.sign < 0) {
      throw new ArgumentError("The multiplicator cannot be negative");
    }

    if (isInfinity) {
      return this;
    }

    if (k.sign == 0) {
      return curve.infinity;
    }

    return _multiplier(this, k, _preCompInfo);
  }
}

/// Base implementation for [ECCurve]
abstract class ECCurveBase implements ECCurve {
  ECFieldElementBase _a;
  ECFieldElementBase _b;

  ECCurveBase(BigInt a, BigInt b) {
    this._a = fromBigInteger(a);
    this._b = fromBigInteger(b);
  }

  ECFieldElementBase get a => _a;
  ECFieldElementBase get b => _b;

  int get fieldSize;
  ECPointBase get infinity;

  ECFieldElementBase fromBigInteger(BigInt x);
  ECPointBase createPoint(BigInt x, BigInt y, [bool withCompression = false]);
  ECPointBase decompressPoint(int yTilde, BigInt X1);

  /**
   * Decode a point on this curve from its ASN.1 encoding. The different
   * encodings are taken account of, including point compression for
   * <code>F<sub>p</sub></code> (X9.62 s 4.2.1 pg 17).
   * @return The decoded point.
   */
  ECPointBase decodePoint(List<int> encoded) {
    ECPointBase p = null;
    int expectedLength = (fieldSize + 7) ~/ 8;

    switch (encoded[0]) {
      case 0x00: // infinity
        if (encoded.length != 1) {
          throw new ArgumentError("Incorrect length for infinity encoding");
        }

        p = infinity;
        break;

      case 0x02: // compressed
      case 0x03: // compressed
        if (encoded.length != (expectedLength + 1)) {
          throw new ArgumentError("Incorrect length for compressed encoding");
        }

        int yTilde = encoded[0] & 1;
        var X1 = _fromArray(encoded, 1, expectedLength);

        p = decompressPoint(yTilde, X1);
        break;

      case 0x04: // uncompressed
      case 0x06: // hybrid
      case 0x07: // hybrid
        if (encoded.length != (2 * expectedLength + 1)) {
          throw new ArgumentError(
              "Incorrect length for uncompressed/hybrid encoding");
        }

        BigInt X1 = _fromArray(encoded, 1, expectedLength);
        BigInt Y1 = _fromArray(encoded, 1 + expectedLength, expectedLength);

        p = createPoint(X1, Y1, false);
        break;

      default:
        throw new ArgumentError(
            "Invalid point encoding 0x" + encoded[0].toRadixString(16));
    }

    return p;
  }

  BigInt _fromArray(List<int> buf, int off, int length) {
    return utils.decodeBigInt(buf.sublist(off, off + length));
  }
}

/// Interface for classes storing precomputation data for multiplication algorithms.
abstract class PreCompInfo {}

/**
 * Interface for functions encapsulating a point multiplication algorithm for [ECPointBase]. Multiplies [p] by [k], i.e. [p] is
 * added [k] times to itself.
 */
typedef ECPointBase ECMultiplier(
    ECPointBase p, BigInt k, PreCompInfo preCompInfo);

bool _testBit(BigInt i, int n) {
  return i & (BigInt.one << n) != BigInt.zero;
}

/// Function implementing the NAF (Non-Adjacent Form) multiplication algorithm.
ECPointBase _FpNafMultiplier(ECPointBase p, BigInt k, PreCompInfo preCompInfo) {
  // TODO Probably should try to add this
  // BigInt e = k.mod(n); // n == order of p
  BigInt e = k;
  BigInt h = e * new BigInt.from(3);

  ECPointBase neg = -p;
  ECPointBase R = p;

  for (var i = h.bitLength - 2; i > 0; --i) {
    R = R.twice();

    var hBit = _testBit(h, i);
    var eBit = _testBit(e, i);

    if (hBit != eBit) {
      R += (hBit ? p : neg);
    }
  }

  return R;
}
