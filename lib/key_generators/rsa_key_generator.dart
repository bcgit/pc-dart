// See file LICENSE for more information.

library impl.key_generator.rsa_key_generator;

import "package:pointycastle/api.dart";
import "package:pointycastle/asymmetric/api.dart";
import "package:pointycastle/key_generators/api.dart";
import "package:pointycastle/src/registry/registry.dart";

bool _testBit(BigInt i, int n) {
  return (i & (BigInt.one << n)) != BigInt.zero;
}

class RSAKeyGenerator implements KeyGenerator {
  static final FactoryConfig FACTORY_CONFIG =
      new StaticFactoryConfig(KeyGenerator, "RSA", () => RSAKeyGenerator());

  SecureRandom _random;
  RSAKeyGeneratorParameters _params;

  String get algorithmName => "RSA";

  @override
  void init(CipherParameters params) {
    if (params is ParametersWithRandom) {
      _random = params.random;
      _params = params.parameters;
    } else {
      _random = new SecureRandom();
      _params = params;
    }

    if (_params.bitStrength < 12) {
      throw new ArgumentError("key bit strength cannot be smaller than 12");
    }

    if (!_testBit(_params.publicExponent, 0)) {
      throw new ArgumentError("Public exponent cannot be even");
    }
  }

  AsymmetricKeyPair generateKeyPair() {
    BigInt p, q, n, e;

    // p and q values should have a length of half the strength in bits
    var strength = _params.bitStrength;
    var pbitlength = (strength + 1) ~/ 2;
    var qbitlength = strength - pbitlength;
    var mindiffbits = strength ~/ 3;

    e = _params.publicExponent;

    // TODO Consider generating safe primes for p, q (see DHParametersHelper.generateSafePrimes)
    // (then p-1 and q-1 will not consist of only small factors - see "Pollard's algorithm")

    // generate p, prime and (p-1) relatively prime to e
    for (;;) {
      p = generateProbablePrime(pbitlength, 1, _random);

      if (p % e == BigInt.one) {
        continue;
      }

      if (!_isProbablePrime(p, _params.certainty)) {
        continue;
      }

      if (e.gcd(p - BigInt.one) == BigInt.one) {
        break;
      }
    }

    // generate a modulus of the required length
    for (;;) {
      // generate q, prime and (q-1) relatively prime to e, and not equal to p
      for (;;) {
        q = generateProbablePrime(qbitlength, 1, _random);

        if ((q - p).abs().bitLength < mindiffbits) {
          continue;
        }

        if (q % e == BigInt.one) {
          continue;
        }

        if (!_isProbablePrime(q, _params.certainty)) {
          continue;
        }

        if (e.gcd(q - BigInt.one) == BigInt.one) {
          break;
        }
      }

      // calculate the modulus
      n = (p * q);

      if (n.bitLength == _params.bitStrength) {
        break;
      }

      // if we get here our primes aren't big enough, make the largest of the two p and try again
      p = (p.compareTo(q) > 0) ? p : q;
    }

    // Swap p and q if necessary
    if (p < q) {
      var swap = p;
      p = q;
      q = swap;
    }

    // calculate the private exponent
    var pSub1 = (p - BigInt.one);
    var qSub1 = (q - BigInt.one);
    var phi = (pSub1 * qSub1);
    var d = e.modInverse(phi);

    return new AsymmetricKeyPair(
        new RSAPublicKey(n, e), new RSAPrivateKey(n, d, p, q, e));
  }
}

/** [List] of low primes */
final List<BigInt> _lowprimes = [
  new BigInt.from(2),
  new BigInt.from(3),
  new BigInt.from(5),
  new BigInt.from(7),
  new BigInt.from(11),
  new BigInt.from(13),
  new BigInt.from(17),
  new BigInt.from(19),
  new BigInt.from(23),
  new BigInt.from(29),
  new BigInt.from(31),
  new BigInt.from(37),
  new BigInt.from(41),
  new BigInt.from(43),
  new BigInt.from(47),
  new BigInt.from(53),
  new BigInt.from(59),
  new BigInt.from(61),
  new BigInt.from(67),
  new BigInt.from(71),
  new BigInt.from(73),
  new BigInt.from(79),
  new BigInt.from(83),
  new BigInt.from(89),
  new BigInt.from(97),
  new BigInt.from(101),
  new BigInt.from(103),
  new BigInt.from(107),
  new BigInt.from(109),
  new BigInt.from(113),
  new BigInt.from(127),
  new BigInt.from(131),
  new BigInt.from(137),
  new BigInt.from(139),
  new BigInt.from(149),
  new BigInt.from(151),
  new BigInt.from(157),
  new BigInt.from(163),
  new BigInt.from(167),
  new BigInt.from(173),
  new BigInt.from(179),
  new BigInt.from(181),
  new BigInt.from(191),
  new BigInt.from(193),
  new BigInt.from(197),
  new BigInt.from(199),
  new BigInt.from(211),
  new BigInt.from(223),
  new BigInt.from(227),
  new BigInt.from(229),
  new BigInt.from(233),
  new BigInt.from(239),
  new BigInt.from(241),
  new BigInt.from(251),
  new BigInt.from(257),
  new BigInt.from(263),
  new BigInt.from(269),
  new BigInt.from(271),
  new BigInt.from(277),
  new BigInt.from(281),
  new BigInt.from(283),
  new BigInt.from(293),
  new BigInt.from(307),
  new BigInt.from(311),
  new BigInt.from(313),
  new BigInt.from(317),
  new BigInt.from(331),
  new BigInt.from(337),
  new BigInt.from(347),
  new BigInt.from(349),
  new BigInt.from(353),
  new BigInt.from(359),
  new BigInt.from(367),
  new BigInt.from(373),
  new BigInt.from(379),
  new BigInt.from(383),
  new BigInt.from(389),
  new BigInt.from(397),
  new BigInt.from(401),
  new BigInt.from(409),
  new BigInt.from(419),
  new BigInt.from(421),
  new BigInt.from(431),
  new BigInt.from(433),
  new BigInt.from(439),
  new BigInt.from(443),
  new BigInt.from(449),
  new BigInt.from(457),
  new BigInt.from(461),
  new BigInt.from(463),
  new BigInt.from(467),
  new BigInt.from(479),
  new BigInt.from(487),
  new BigInt.from(491),
  new BigInt.from(499),
  new BigInt.from(503),
  new BigInt.from(509)
];

final BigInt _lplim = (BigInt.one << 26) ~/ _lowprimes.last;

final BigInt _bigTwo = new BigInt.from(2);

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

/** true if probably prime (HAC 4.24, Miller-Rabin) */
bool _millerRabin(BigInt b, int t) {
  // Implementation borrowed from bignum.BigIntegerDartvm.
  var n1 = b - BigInt.one;
  var k = _lbit(n1);
  if (k <= 0) return false;
  var r = n1 >> k;
  t = (t + 1) >> 1;
  if (t > _lowprimes.length) t = _lowprimes.length;
  BigInt a;
  for (var i = 0; i < t; ++i) {
    a = _lowprimes[i];
    var y = a.modPow(r, b);
    if (y.compareTo(BigInt.one) != 0 && y.compareTo(n1) != 0) {
      var j = 1;
      while (j++ < k && y.compareTo(n1) != 0) {
        y = y.modPow(_bigTwo, b);
        if (y.compareTo(BigInt.one) == 0) return false;
      }
      if (y.compareTo(n1) != 0) return false;
    }
  }
  return true;
}

/** test primality with certainty >= 1-.5^t */
bool _isProbablePrime(BigInt b, int t) {
  // Implementation borrowed from bignum.BigIntegerDartvm.
  var i, x = b.abs();
  if (b <= _lowprimes.last) {
    for (i = 0; i < _lowprimes.length; ++i) if (b == _lowprimes[i]) return true;
    return false;
  }
  if (x.isEven) return false;
  i = 1;
  while (i < _lowprimes.length) {
    var m = _lowprimes[i], j = i + 1;
    while (j < _lowprimes.length && m < _lplim) m *= _lowprimes[j++];
    m = x % m;
    while (i < j) if (m % _lowprimes[i++] == 0) return false;
  }
  return _millerRabin(x, t);
}

BigInt generateProbablePrime(int bitLength, int certainty, SecureRandom rnd) {
  if (bitLength < 2) {
    return BigInt.one;
  }

  BigInt candidate = rnd.nextBigInteger(bitLength);

  // force MSB set
  if (!_testBit(candidate, bitLength - 1)) {
    candidate |= BigInt.one << (bitLength - 1);
  }

  // force odd
  if (candidate.isEven) {
    candidate += BigInt.one;
  }

  while (!_isProbablePrime(candidate, certainty)) {
    candidate += _bigTwo;
    if (candidate.bitLength > bitLength) {
      candidate -= BigInt.one << (bitLength - 1);
    }
  }

  return candidate;
}
