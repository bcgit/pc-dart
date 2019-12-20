// See file LICENSE for more information.

library pointycastle.benchmark.digests.ripemd320_benchmark;

import "../benchmark/digest_benchmark.dart";

main() {
  new DigestBenchmark("RIPEMD-320").report();
}
