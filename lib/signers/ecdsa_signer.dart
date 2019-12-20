// See file LICENSE for more information.

library pointycastle.impl.signer.ecdsa_signer;

import "dart:typed_data";
import "dart:math";

import "package:pointycastle/api.dart";
import "package:pointycastle/ecc/api.dart";
import "package:pointycastle/src/utils.dart" as utils;
import "package:pointycastle/src/registry/registry.dart";

bool _testBit(BigInt i, int n) {
  return (i & (BigInt.one << n)) != BigInt.zero;
}

class ECDSASigner implements Signer {
  /// Intended for internal use.
  static final FactoryConfig FACTORY_CONFIG = new DynamicFactoryConfig.regex(
      Signer, r"^(.+)/(DET-)?ECDSA$", (_, final Match match) {
    final String digestName = match.group(1);
    final bool withMac = match.group(2) != null;
    return () {
      Digest underlyingDigest = new Digest(digestName);
      Mac mac = withMac ? new Mac("${digestName}/HMAC") : null;
      return new ECDSASigner(underlyingDigest, mac);
    };
  });

  ECPublicKey _pbkey;
  ECPrivateKey _pvkey;
  SecureRandom _random;
  bool _deterministic;
  Digest _digest;
  Mac _kMac;

  /**
   * If [_digest] is not null it is used to hash the message before signing and verifying, otherwise, the message needs to be
   * hashed by the user of this [ECDSASigner] object.
   * If [_kMac] is not null, RFC 6979 is used for k calculation with the given [Mac]. Keep in mind that, to comply with
   * RFC 69679, [_kMac] must be HMAC with the same digest used to hash the message.
   */
  ECDSASigner([this._digest = null, this._kMac = null]);

  String get algorithmName =>
      "${_digest.algorithmName}/${_kMac == null ? "" : "DET-"}ECDSA";

  void reset() {}

  /**
   * Init this [Signer]. The [params] argument can be:
   * -A [ParametersWithRandom] containing a [PrivateKeyParameter] or a raw [PrivateKeyParameter] for signing
   * -An [PublicKeyParameter] for verifying.
   */
  void init(bool forSigning, CipherParameters params) {
    _pbkey = _pvkey = null;

    if (forSigning) {
      PrivateKeyParameter pvparams;

      if (params is ParametersWithRandom) {
        _random = params.random;
        pvparams = params.parameters;
      } else if (_kMac != null) {
        _random = null;
        pvparams = params;
      } else {
        _random = new SecureRandom();
        pvparams = params;
      }

      if (pvparams is! PrivateKeyParameter) {
        throw new ArgumentError(
            "Unsupported parameters type ${pvparams.runtimeType}: should be PrivateKeyParameter");
      }
      _pvkey = pvparams.key;
    } else {
      PublicKeyParameter pbparams;

      pbparams = params;

      if (pbparams is! PublicKeyParameter) {
        throw new ArgumentError(
            "Unsupported parameters type ${pbparams.runtimeType}: should be PublicKeyParameter");
      }
      _pbkey = pbparams.key;
    }
  }

  Signature generateSignature(Uint8List message) {
    message = _hashMessageIfNeeded(message);

    var n = _pvkey.parameters.n;
    var e = _calculateE(n, message);
    var r = null;
    var s = null;

    var kCalculator;
    if (_kMac != null) {
      kCalculator = new _RFC6979KCalculator(_kMac, n, _pvkey.d, message);
    } else {
      kCalculator = new _RandomKCalculator(n, _random);
    }

    // 5.3.2
    do {
      // generate s
      var k = null;

      do {
        // generate r
        k = kCalculator.nextK();

        var p = _pvkey.parameters.G * k;

        // 5.3.3
        var x = p.x.toBigInteger();

        r = x % n;
      } while (r == BigInt.zero);

      var d = _pvkey.d;

      s = (k.modInverse(n) * (e + (d * r))) % n;
    } while (s == BigInt.zero);

    return new ECSignature(r, s);
  }

  bool verifySignature(Uint8List message, covariant ECSignature signature) {
    message = _hashMessageIfNeeded(message);

    var n = _pbkey.parameters.n;
    var e = _calculateE(n, message);

    var r = signature.r;
    var s = signature.s;

    // r in the range [1,n-1]
    if (r.compareTo(BigInt.one) < 0 || r.compareTo(n) >= 0) {
      return false;
    }

    // s in the range [1,n-1]
    if (s.compareTo(BigInt.one) < 0 || s.compareTo(n) >= 0) {
      return false;
    }

    var c = s.modInverse(n);

    var u1 = (e * c) % n;
    var u2 = (r * c) % n;

    var G = _pbkey.parameters.G;
    var Q = _pbkey.Q;

    var point = _sumOfTwoMultiplies(G, u1, Q, u2);

    // components must be bogus.
    if (point.isInfinity) {
      return false;
    }

    var v = point.x.toBigInteger() % n;

    return v == r;
  }

  Uint8List _hashMessageIfNeeded(Uint8List message) {
    if (_digest != null) {
      _digest.reset();
      return _digest.process(message);
    } else {
      return message;
    }
  }

  BigInt _calculateE(BigInt n, Uint8List message) {
    var log2n = n.bitLength;
    var messageBitLength = message.length * 8;

    if (log2n >= messageBitLength) {
      return utils.decodeBigInt(message);
    } else {
      BigInt trunc = utils.decodeBigInt(message);

      trunc = trunc >> (messageBitLength - log2n);

      return trunc;
    }
  }

  ECPoint _sumOfTwoMultiplies(ECPoint P, BigInt a, ECPoint Q, BigInt b) {
    ECCurve c = P.curve;

    if (c != Q.curve) {
      throw new ArgumentError("P and Q must be on same curve");
    }

    // Point multiplication for Koblitz curves (using WTNAF) beats Shamir's trick
    /* TODO: uncomment this when F2m available
    if( c is ECCurve.F2m ) {
      ECCurve.F2m f2mCurve = (ECCurve.F2m)c;
      if( f2mCurve.isKoblitz() ) {
        return P.multiply(a).add(Q.multiply(b));
      }
    }
    */

    return _implShamirsTrick(P, a, Q, b);
  }

  ECPoint _implShamirsTrick(ECPoint P, BigInt k, ECPoint Q, BigInt l) {
    int m = max(k.bitLength, l.bitLength);

    ECPoint Z = P + Q;
    ECPoint R = P.curve.infinity;

    for (int i = m - 1; i >= 0; --i) {
      R = R.twice();

      if (_testBit(k, i)) {
        if (_testBit(l, i)) {
          R = R + Z;
        } else {
          R = R + P;
        }
      } else {
        if (_testBit(l, i)) {
          R = R + Q;
        }
      }
    }

    return R;
  }
}

class _RFC6979KCalculator {
  Mac _mac;
  Uint8List _K;
  Uint8List _V;
  BigInt _n;

  _RFC6979KCalculator(this._mac, this._n, BigInt d, Uint8List message) {
    _V = new Uint8List(_mac.macSize);
    _K = new Uint8List(_mac.macSize);
    _init(d, message);
  }

  void _init(BigInt d, Uint8List message) {
    _V.fillRange(0, _V.length, 0x01);
    _K.fillRange(0, _K.length, 0x00);

    var x = new Uint8List((_n.bitLength + 7) ~/ 8);
    var dVal = _asUnsignedByteArray(d);

    x.setRange((x.length - dVal.length), x.length, dVal);

    var m = new Uint8List((_n.bitLength + 7) ~/ 8);

    var mInt = _bitsToInt(message);

    if (mInt > _n) {
      mInt -= _n;
    }

    var mVal = _asUnsignedByteArray(mInt);

    m.setRange((m.length - mVal.length), m.length, mVal);

    _mac.init(new KeyParameter(_K));

    _mac.update(_V, 0, _V.length);
    _mac.updateByte(0x00);
    _mac.update(x, 0, x.length);
    _mac.update(m, 0, m.length);
    _mac.doFinal(_K, 0);

    _mac.init(new KeyParameter(_K));
    _mac.update(_V, 0, _V.length);
    _mac.doFinal(_V, 0);

    _mac.update(_V, 0, _V.length);
    _mac.updateByte(0x01);
    _mac.update(x, 0, x.length);
    _mac.update(m, 0, m.length);
    _mac.doFinal(_K, 0);

    _mac.init(new KeyParameter(_K));
    _mac.update(_V, 0, _V.length);
    _mac.doFinal(_V, 0);
  }

  BigInt nextK() {
    var t = new Uint8List((_n.bitLength + 7) ~/ 8);

    for (;;) {
      var tOff = 0;

      while (tOff < t.length) {
        _mac.update(_V, 0, _V.length);
        _mac.doFinal(_V, 0);

        if ((t.length - tOff) < _V.length) {
          t.setRange(tOff, t.length, _V);
          tOff += (t.length - tOff);
        } else {
          t.setRange(tOff, tOff + _V.length, _V);
          tOff += _V.length;
        }
      }

      var k = _bitsToInt(t);

      if ((k == 0) || (k >= _n)) {
        _mac.update(_V, 0, _V.length);
        _mac.updateByte(0x00);
        _mac.doFinal(_K, 0);

        _mac.init(new KeyParameter(_K));
        _mac.update(_V, 0, _V.length);
        _mac.doFinal(_V, 0);
      } else {
        return k;
      }
    }
  }

  BigInt _bitsToInt(Uint8List t) {
    var v = utils.decodeBigInt(t);
    if ((t.length * 8) > _n.bitLength) {
      v = v >> ((t.length * 8) - _n.bitLength);
    }

    return v;
  }

  Uint8List _asUnsignedByteArray(BigInt value) {
    var bytes = utils.encodeBigInt(value);

    if (bytes[0] == 0) {
      return new Uint8List.fromList(bytes.sublist(1));
    } else {
      return new Uint8List.fromList(bytes);
    }
  }
}

class _RandomKCalculator {
  BigInt _n;
  SecureRandom _random;

  _RandomKCalculator(this._n, this._random);

  BigInt nextK() {
    var k;
    do {
      k = _random.nextBigInteger(_n.bitLength);
    } while (k == BigInt.zero || k >= _n);
    return k;
  }
}
