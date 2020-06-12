// See file LICENSE for more information.

library benchmark.digests.sha384_benchmark;

import "../benchmark/digest_benchmark.dart";

main() {
  new DigestBenchmark("SHA-384").report();
}
