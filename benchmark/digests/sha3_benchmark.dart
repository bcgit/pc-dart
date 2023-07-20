// See file LICENSE for more information.

import '../benchmark/digest_benchmark.dart';

void main() {
  DigestBenchmark('SHA-3/224').report();
  DigestBenchmark('SHA-3/256').report();
  DigestBenchmark('SHA-3/288').report();
  DigestBenchmark('SHA-3/384').report();
  DigestBenchmark('SHA-3/512').report();
}
