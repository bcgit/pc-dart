
library pointycastle.benchmark.digests.blake2b_benchmark;

import "../benchmark/digest_benchmark.dart";

main() {
  new DigestBenchmark("Blake2b").report();
}
