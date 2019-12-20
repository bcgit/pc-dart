// See file LICENSE for more information.

library pointycastle.benchmark.digests.sha256_benchmark;

import "../benchmark/digest_benchmark.dart";

main() {
  new DigestBenchmark("SHA-256").report();
}
