// See file LICENSE for more information.

library benchmark.digests.ripemd256_benchmark;

import "../benchmark/digest_benchmark.dart";

main() {
  new DigestBenchmark("RIPEMD-256").report();
}
