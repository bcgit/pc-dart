// See file LICENSE for more information.

library pointycastle.benchmark.benchmark.digest_benchmark;

import "dart:typed_data";

import "package:pointycastle/pointycastle.dart";

import "../benchmark/rate_benchmark.dart";

class DigestBenchmark extends RateBenchmark {
  final String _digestName;
  final Uint8List _data;

  Digest _digest;

  DigestBenchmark(String digestName, [int dataLength = 1024 * 1024])
      : _digestName = digestName,
        _data = new Uint8List(dataLength),
        super("Digest | $digestName");

  void setup() {
    _digest = new Digest(_digestName);
  }

  void run() {
    _digest.process(_data);
    addSample(_data.length);
  }
}
