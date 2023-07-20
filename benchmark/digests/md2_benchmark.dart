// See file LICENSE for more information.

import '../benchmark/digest_benchmark.dart';

void main() {
  DigestBenchmark('MD2', 256 * 1024).report();
}
