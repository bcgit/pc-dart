// See file LICENSE for more information.

library pointycastle.impl.ec_domain_parameters.prime192v3;

import "package:pointycastle/ecc/api.dart";
import "package:pointycastle/ecc/ecc_base.dart";
import "package:pointycastle/src/ec_standard_curve_constructor.dart";
import "package:pointycastle/src/registry/registry.dart";

class ECCurve_prime192v3 extends ECDomainParametersImpl {
  static final FactoryConfig FACTORY_CONFIG = new StaticFactoryConfig(
      ECDomainParameters, "prime192v3", () => ECCurve_prime192v3());

  factory ECCurve_prime192v3() => constructFpStandardCurve(
      "prime192v3", ECCurve_prime192v3._make,
      q: BigInt.parse("fffffffffffffffffffffffffffffffeffffffffffffffff",
          radix: 16),
      a: BigInt.parse("fffffffffffffffffffffffffffffffefffffffffffffffc",
          radix: 16),
      b: BigInt.parse("22123dc2395a05caa7423daeccc94760a7d462256bd56916",
          radix: 16),
      g: BigInt.parse("027d29778100c65a1da1783716588dce2b8b4aee8e228f1896",
          radix: 16),
      n: BigInt.parse("ffffffffffffffffffffffff7a62d031c83f4294f640ec13",
          radix: 16),
      h: BigInt.parse("1", radix: 16),
      seed:
          BigInt.parse("c469684435deb378c4b65ca9591e2a5763059a2e", radix: 16));

  static ECCurve_prime192v3 _make(domainName, curve, G, n, _h, seed) =>
      new ECCurve_prime192v3._super(domainName, curve, G, n, _h, seed);

  ECCurve_prime192v3._super(domainName, curve, G, n, _h, seed)
      : super(domainName, curve, G, n, _h, seed);
}
