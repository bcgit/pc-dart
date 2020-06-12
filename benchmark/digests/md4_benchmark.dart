// See file LICENSE for more information.

library benchmark.digests.md4_benchmark;

import "../benchmark/digest_benchmark.dart";

main() {
  new DigestBenchmark("MD4").report();
}
