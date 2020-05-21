// See file LICENSE for more information.

library pointycastle.benchmark.digests.sha512_benchmark;

import "../benchmark/digest_benchmark.dart";

main() {
  new DigestBenchmark("SHA-512").report();
}
