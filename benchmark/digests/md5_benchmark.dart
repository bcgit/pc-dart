// See file LICENSE for more information.

library benchmark.digests.md5_benchmark;

import "../benchmark/digest_benchmark.dart";

main() {
  new DigestBenchmark("MD5").report();
}
