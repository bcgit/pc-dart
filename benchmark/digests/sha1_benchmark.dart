// See file LICENSE for more information.

library pointycastle.benchmark.digests.sha1_benchmark;

import "../benchmark/digest_benchmark.dart";

main() {
  new DigestBenchmark("SHA-1").report();
}
