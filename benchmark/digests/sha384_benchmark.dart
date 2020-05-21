// See file LICENSE for more information.

library pointycastle.benchmark.digests.sha384_benchmark;

import "../benchmark/digest_benchmark.dart";

main() {
  new DigestBenchmark("SHA-384").report();
}
