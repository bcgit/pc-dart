// See file LICENSE for more information.

library benchmark.digests.sha224_benchmark;

import "../benchmark/digest_benchmark.dart";

main() {
  new DigestBenchmark("SHA-224").report();
}
