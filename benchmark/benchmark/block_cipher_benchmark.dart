// See file LICENSE for more information.

library pointycastle.benchmark.benchmark.block_cipher_benchmark;

import "dart:typed_data";

import "package:pointycastle/pointycastle.dart";

import "../benchmark/rate_benchmark.dart";

typedef CipherParameters CipherParametersFactory();

class BlockCipherBenchmark extends RateBenchmark {
  final String _blockCipherName;
  final bool _forEncryption;
  final CipherParametersFactory _cipherParametersFactory;
  Uint8List _data;

  BlockCipher _blockCipher;

  BlockCipherBenchmark(String blockCipherName, String blockCipherVariant,
      bool forEncryption, this._cipherParametersFactory)
      : _blockCipherName = blockCipherName,
        _forEncryption = forEncryption,
        super("BlockCipher | $blockCipherName - $blockCipherVariant - "
            "${forEncryption ? 'encrypt' : 'decrypt'}");

  void setup() {
    _blockCipher = new BlockCipher(_blockCipherName);
    _blockCipher.init(_forEncryption, _cipherParametersFactory());
    _data = new Uint8List(_blockCipher.blockSize);
  }

  void run() {
    _blockCipher.process(_data);
    addSample(_data.length);
  }
}
