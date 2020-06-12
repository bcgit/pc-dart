// See file LICENSE for more information.

library benchmark.digests.whirlpool_benchmark;

import "../benchmark/digest_benchmark.dart";

main() {
  new DigestBenchmark("Whirlpool").report();
}
