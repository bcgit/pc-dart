// See file LICENSE for more information.

library impl.digest.sha3;

import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/src/impl/base_digest.dart';
import 'package:pointycastle/src/registry/registry.dart';
import 'package:pointycastle/src/ufixnum.dart';

/// Implementation of SHA3 digest.
/// https://csrc.nist.gov/publications/detail/fips/202/final
class SHA3Digest extends BaseDigest implements Digest, ExtendedDigest {
  static final RegExp _sha3REGEX = RegExp(r'^SHA3-([0-9]+)$');

  /// Intended for internal use.
  static final FactoryConfig factoryConfig = DynamicFactoryConfig(
      Digest,
      _sha3REGEX,
      (_, final Match match) => () {
            var bitLength = int.parse(match.group(1));
            return SHA3Digest(bitLength);
          });

  static final _keccakRoundConstants = Register64List.from([
    [0x00000000, 0x00000001],
    [0x00000000, 0x00008082],
    [0x80000000, 0x0000808a],
    [0x80000000, 0x80008000],
    [0x00000000, 0x0000808b],
    [0x00000000, 0x80000001],
    [0x80000000, 0x80008081],
    [0x80000000, 0x00008009],
    [0x00000000, 0x0000008a],
    [0x00000000, 0x00000088],
    [0x00000000, 0x80008009],
    [0x00000000, 0x8000000a],
    [0x00000000, 0x8000808b],
    [0x80000000, 0x0000008b],
    [0x80000000, 0x00008089],
    [0x80000000, 0x00008003],
    [0x80000000, 0x00008002],
    [0x80000000, 0x00000080],
    [0x00000000, 0x0000800a],
    [0x80000000, 0x8000000a],
    [0x80000000, 0x80008081],
    [0x80000000, 0x00008080],
    [0x00000000, 0x80000001],
    [0x80000000, 0x80008008]
  ]);

  static final _keccakRhoOffsets = [
    0x00000000,
    0x00000001,
    0x0000003e,
    0x0000001c,
    0x0000001b,
    0x00000024,
    0x0000002c,
    0x00000006,
    0x00000037,
    0x00000014,
    0x00000003,
    0x0000000a,
    0x0000002b,
    0x00000019,
    0x00000027,
    0x00000029,
    0x0000002d,
    0x0000000f,
    0x00000015,
    0x00000008,
    0x00000012,
    0x00000002,
    0x0000003d,
    0x00000038,
    0x0000000e
  ];

  int _rate;
  int _fixedOutputLength;

  final _state = Uint8List(200);
  final _dataQueue = Uint8List(192);

  int _bitsInQueue;
  bool _squeezing;

  int _bitsAvailableForSqueezing;

  SHA3Digest([int bitLength = 288]) {
    switch (bitLength) {
      case 224:
      case 256:
      case 384:
      case 512:
        _init(bitLength);
        break;
      default:
        throw StateError(
            'invalid bitLength ($bitLength) for SHA-3 must only be 224,256,384,512');
    }
  }

  @override
  String get algorithmName => 'SHA3-$_fixedOutputLength';

  @override
  int get digestSize => (_fixedOutputLength ~/ 8);

  @override
  void reset() {
    _init(_fixedOutputLength);
  }

  @override
  void updateByte(int inp) {
    _doUpdate(Uint8List.fromList([inp]), 0, 8);
  }

  @override
  void update(Uint8List inp, int inpOff, int len) {
    _doUpdate(inp, inpOff, len * 8);
  }

  @override
  int doFinal(Uint8List out, int outOff) {
    // FIPS 202 SHA3 https://github.com/PointyCastle/pointycastle/issues/128
    absorbBits(0x02, 2);
    _squeeze(out, outOff, _fixedOutputLength);
    reset();
    return digestSize;
  }

  void absorbBits(int data, int bits) {
    if (bits < 1 || bits > 7) {
      throw StateError('"bits" must be in the range 1 to 7');
    }
    if ((_bitsInQueue % 8) != 0) {
      throw StateError('attempt to absorb with odd length queue');
    }
    if (_squeezing) {
      throw StateError('attempt to absorb while squeezing');
    }
    var mask = (1 << bits) - 1;
    _dataQueue[_bitsInQueue >> 3] = data & mask;
    _bitsInQueue += bits;
  }

  void _clearDataQueueSection(int off, int len) {
    _dataQueue.fillRange(off, off + len, 0);
  }

  void _doUpdate(Uint8List data, int off, int databitlen) {
    if ((databitlen % 8) == 0) {
      _absorb(data, off, databitlen);
    } else {
      _absorb(data, off, databitlen - (databitlen % 8));

      var lastByte = Uint8List(1);

      lastByte[0] = data[off + (databitlen ~/ 8)] >> (8 - (databitlen % 8));
      _absorb(lastByte, off, databitlen % 8);
    }
  }

  void _init(int bitlen) {
    _initSponge(1600 - (bitlen << 1));
  }

  void _initSponge(int rate) {
    if ((rate <= 0) || (rate >= 1600) || ((rate % 64) != 0)) {
      throw StateError('invalid rate value');
    }

    _rate = rate;
    _fixedOutputLength = (1600 - rate) ~/ 2;
    _state.fillRange(0, _state.length, 0);
    _dataQueue.fillRange(0, _dataQueue.length, 0);

    _bitsInQueue = 0;
    _squeezing = false;
    _bitsAvailableForSqueezing = 0;
  }

  void _absorbQueue() {
    _keccakAbsorb(_state, _dataQueue, _rate ~/ 8);

    _bitsInQueue = 0;
  }

  void _absorb(Uint8List data, int off, int databitlen) {
    int i, j, wholeBlocks;

    if ((_bitsInQueue % 8) != 0) {
      throw StateError('Attempt to absorb with odd length queue');
    }

    if (_squeezing) {
      throw StateError('Attempt to absorb while squeezing');
    }

    i = 0;
    while (i < databitlen) {
      if ((_bitsInQueue == 0) &&
          (databitlen >= _rate) &&
          (i <= (databitlen - _rate))) {
        wholeBlocks = (databitlen - i) ~/ _rate;

        for (j = 0; j < wholeBlocks; j++) {
          final chunk = Uint8List(_rate ~/ 8);

          final offset = (off + (i ~/ 8) + (j * chunk.length));
          chunk.setRange(0, chunk.length, data.sublist(offset));

          _keccakAbsorb(_state, chunk, chunk.length);
        }

        i += wholeBlocks * _rate;
      } else {
        var partialBlock = (databitlen - i);

        if ((partialBlock + _bitsInQueue) > _rate) {
          partialBlock = (_rate - _bitsInQueue);
        }

        final partialByte = (partialBlock % 8);
        partialBlock -= partialByte;

        final start = (_bitsInQueue ~/ 8);
        final end = start + (partialBlock ~/ 8);
        final offset = (off + (i ~/ 8));
        _dataQueue.setRange(start, end, data.sublist(offset));

        _bitsInQueue += partialBlock;
        i += partialBlock;
        if (_bitsInQueue == _rate) {
          _absorbQueue();
        }
        if (partialByte > 0) {
          var mask = (1 << partialByte) - 1;
          _dataQueue[_bitsInQueue ~/ 8] = (data[off + (i ~/ 8)] & mask);
          _bitsInQueue += partialByte;
          i += partialByte;
        }
      }
    }
  }

  void _padAndSwitchToSqueezingPhase() {
    if (_bitsInQueue + 1 == _rate) {
      _dataQueue[_bitsInQueue ~/ 8] |= 1 << (_bitsInQueue % 8);
      _absorbQueue();
      _clearDataQueueSection(0, _rate ~/ 8);
    } else {
      _clearDataQueueSection(
          ((_bitsInQueue + 7) ~/ 8), (_rate ~/ 8 - (_bitsInQueue + 7) ~/ 8));
      _dataQueue[_bitsInQueue ~/ 8] |= 1 << (_bitsInQueue % 8);
    }
    _dataQueue[(_rate - 1) ~/ 8] |= 1 << ((_rate - 1) % 8);
    _absorbQueue();

    if (_rate == 1024) {
      _keccakExtract1024bits(_state, _dataQueue);
      _bitsAvailableForSqueezing = 1024;
    } else {
      _keccakExtract(_state, _dataQueue, _rate ~/ 64);
      _bitsAvailableForSqueezing = _rate;
    }

    _squeezing = true;
  }

  void _squeeze(Uint8List output, int offset, int outputLength) {
    int i, partialBlock;

    if (!_squeezing) {
      _padAndSwitchToSqueezingPhase();
    }

    if ((outputLength % 8) != 0) {
      throw StateError('Output length not a multiple of 8: $outputLength');
    }

    i = 0;
    while (i < outputLength) {
      if (_bitsAvailableForSqueezing == 0) {
        _keccakPermutation(_state);

        if (_rate == 1024) {
          _keccakExtract1024bits(_state, _dataQueue);
          _bitsAvailableForSqueezing = 1024;
        } else {
          _keccakExtract(_state, _dataQueue, _rate ~/ 64);
          _bitsAvailableForSqueezing = _rate;
        }
      }
      partialBlock = _bitsAvailableForSqueezing;
      if (partialBlock > (outputLength - i)) {
        partialBlock = (outputLength - i);
      }

      var start = (offset + (i ~/ 8));
      var end = start + (partialBlock ~/ 8);
      var offset2 = (_rate - _bitsAvailableForSqueezing) ~/ 8;
      output.setRange(start, end, _dataQueue.sublist(offset2));
      _bitsAvailableForSqueezing -= partialBlock;
      i += partialBlock;
    }
  }

  void _fromBytesToWords(Register64List stateAsWords, Uint8List state) {
    final r = Register64();

    for (var i = 0; i < (1600 ~/ 64); i++) {
      final index = i * (64 ~/ 8);

      stateAsWords[i].set(0);

      for (var j = 0; j < (64 ~/ 8); j++) {
        r.set(state[index + j]);
        r.shiftl(8 * j);
        stateAsWords[i].or(r);
      }
    }
  }

  void _fromWordsToBytes(Uint8List state, Register64List stateAsWords) {
    final r = Register64();

    for (var i = 0; i < (1600 ~/ 64); i++) {
      final index = i * (64 ~/ 8);

      for (var j = 0; j < (64 ~/ 8); j++) {
        r.set(stateAsWords[i]);
        r.shiftr(8 * j);
        state[index + j] = r.lo32;
      }
    }
  }

  void _keccakPermutation(Uint8List state) {
    final longState = Register64List(state.length ~/ 8);

    _fromBytesToWords(longState, state);
    _keccakPermutationOnWords(longState);
    _fromWordsToBytes(state, longState);
  }

  void _keccakPermutationAfterXor(
      Uint8List state, Uint8List data, int dataLengthInBytes) {
    for (var i = 0; i < dataLengthInBytes; i++) {
      state[i] ^= data[i];
    }
    _keccakPermutation(state);
  }

  void _keccakPermutationOnWords(Register64List state) {
    for (var i = 0; i < 24; i++) {
      theta(state);
      rho(state);
      pi(state);
      chi(state);
      _iota(state, i);
    }
  }

  void theta(Register64List A) {
    final C = Register64List(5);
    final r0 = Register64();
    final r1 = Register64();

    for (var x = 0; x < 5; x++) {
      C[x].set(0);

      for (var y = 0; y < 5; y++) {
        C[x].xor(A[x + 5 * y]);
      }
    }

    for (var x = 0; x < 5; x++) {
      r0.set(C[(x + 1) % 5]);
      r0.shiftl(1);

      r1.set(C[(x + 1) % 5]);
      r1.shiftr(63);

      r0.xor(r1);
      r0.xor(C[(x + 4) % 5]);

      for (var y = 0; y < 5; y++) {
        A[x + 5 * y].xor(r0);
      }
    }
  }

  void rho(Register64List A) {
    final r = Register64();

    for (var x = 0; x < 5; x++) {
      for (var y = 0; y < 5; y++) {
        final index = x + 5 * y;

        if (_keccakRhoOffsets[index] != 0) {
          r.set(A[index]);
          r.shiftr(64 - _keccakRhoOffsets[index]);

          A[index].shiftl(_keccakRhoOffsets[index]);
          A[index].xor(r);
        }
      }
    }
  }

  void pi(Register64List A) {
    final tempA = Register64List(25);

    tempA.setRange(0, tempA.length, A);

    for (var x = 0; x < 5; x++) {
      for (var y = 0; y < 5; y++) {
        A[y + 5 * ((2 * x + 3 * y) % 5)].set(tempA[x + 5 * y]);
      }
    }
  }

  void chi(Register64List A) {
    final chiC = Register64List(5);

    for (var y = 0; y < 5; y++) {
      for (var x = 0; x < 5; x++) {
        chiC[x].set(A[((x + 1) % 5) + (5 * y)]);
        chiC[x].not();
        chiC[x].and(A[((x + 2) % 5) + (5 * y)]);
        chiC[x].xor(A[x + 5 * y]);
      }
      for (var x = 0; x < 5; x++) {
        A[x + 5 * y].set(chiC[x]);
      }
    }
  }

  void _iota(Register64List A, int indexRound) {
    A[(((0) % 5) + 5 * ((0) % 5))].xor(_keccakRoundConstants[indexRound]);
  }

  void _keccakAbsorb(Uint8List byteState, Uint8List data, int dataInBytes) {
    _keccakPermutationAfterXor(byteState, data, dataInBytes);
  }

  void _keccakExtract1024bits(Uint8List byteState, Uint8List data) {
    data.setRange(0, 128, byteState);
  }

  void _keccakExtract(Uint8List byteState, Uint8List data, int laneCount) {
    data.setRange(0, laneCount * 8, byteState);
  }

  @override
  int getByteLength() => _rate ~/ 8;
}
