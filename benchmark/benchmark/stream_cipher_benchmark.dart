// See file LICENSE for more information.

library pointycastle.benchmark.benchmark.stream_cipher_benchmark;

import "dart:typed_data";

import "package:pointycastle/pointycastle.dart";

import "../benchmark/rate_benchmark.dart";

typedef CipherParameters CipherParametersFactory();

class StreamCipherBenchmark extends RateBenchmark {
  final String _streamCipherName;
  final bool _forEncryption;
  final CipherParametersFactory _cipherParametersFactory;
  final Uint8List _data;

  StreamCipher _streamCipher;

  StreamCipherBenchmark(String streamCipherName, String streamCipherVariant,
      bool forEncryption, this._cipherParametersFactory,
      [int dataLength = 1024 * 1024])
      : _streamCipherName = streamCipherName,
        _forEncryption = forEncryption,
        _data = new Uint8List(dataLength),
        super(
            "StreamCipher | $streamCipherName ${_formatVariant(streamCipherVariant)}- "
            "${forEncryption ? 'encrypt' : 'decrypt'}");

  void setup() {
    _streamCipher = new StreamCipher(_streamCipherName);
    _streamCipher.init(_forEncryption, _cipherParametersFactory());
  }

  void run() {
    _streamCipher.process(_data);
    addSample(_data.length);
  }
}

String _formatVariant(String streamCipherVariant) {
  if (streamCipherVariant == null) {
    return "";
  } else {
    return "- $streamCipherVariant ";
  }
}
