// See file LICENSE for more information.

library pointycastle.benchmark.digests.md2_benchmark;

import "../benchmark/digest_benchmark.dart";

main() {
  new DigestBenchmark("MD2", 256 * 1024).report();
}
