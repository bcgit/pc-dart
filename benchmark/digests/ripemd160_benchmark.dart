// See file LICENSE for more information.

library pointycastle.benchmark.digests.ripemd160_benchmark;

import "../benchmark/digest_benchmark.dart";

main() {
  new DigestBenchmark("RIPEMD-160").report();
}
