// See file LICENSE for more information.

library src.ufixnum;

import 'dart:typed_data';

const _MASK_3 = 0x07;
const _MASK_5 = 0x1F;
const _MASK_6 = 0x3F;
const _MASK_8 = 0xFF;
const _MASK_16 = 0xFFFF;
const _MASK_32 = 0xFFFFFFFF;

// ignore: non_constant_identifier_names
final _MASK32_HI_BITS = [
  0xFFFFFFFF,
  0x7FFFFFFF,
  0x3FFFFFFF,
  0x1FFFFFFF,
  0x0FFFFFFF,
  0x07FFFFFF,
  0x03FFFFFF,
  0x01FFFFFF,
  0x00FFFFFF,
  0x007FFFFF,
  0x003FFFFF,
  0x001FFFFF,
  0x000FFFFF,
  0x0007FFFF,
  0x0003FFFF,
  0x0001FFFF,
  0x0000FFFF,
  0x00007FFF,
  0x00003FFF,
  0x00001FFF,
  0x00000FFF,
  0x000007FF,
  0x000003FF,
  0x000001FF,
  0x000000FF,
  0x0000007F,
  0x0000003F,
  0x0000001F,
  0x0000000F,
  0x00000007,
  0x00000003,
  0x00000001,
  0x00000000
];

////////////////////////////////////////////////////////////////////////////////////////////////////
// 8 bit operations
//
int clip8(int x) => (x & _MASK_8);

int csum8(int x, int y) => sum8(clip8(x), clip8(y));
int sum8(int x, int y) {
  assert((x >= 0) && (x <= _MASK_8));
  assert((y >= 0) && (y <= _MASK_8));
  return ((x + y) & _MASK_8);
}

int csub8(int x, int y) => sub8(clip8(x), clip8(y));
int sub8(int x, int y) {
  assert((x >= 0) && (x <= _MASK_8));
  assert((y >= 0) && (y <= _MASK_8));
  return ((x - y) & _MASK_8);
}

int cshiftl8(int x, int n) => shiftl8(clip8(x), n);
int shiftl8(int x, int n) {
  assert((x >= 0) && (x <= _MASK_8));
  return ((x << (n & _MASK_3)) & _MASK_8);
}

int cshiftr8(int x, int n) => shiftr8(clip8(x), n);
int shiftr8(int x, int n) {
  assert((x >= 0) && (x <= _MASK_8));
  return (x >> (n & _MASK_3));
}

int cneg8(int x) => neg8(clip8(x));
int neg8(int x) {
  assert((x >= 0) && (x <= _MASK_8));
  return (-x & _MASK_8);
}

int cnot8(int x) => not8(clip8(x));
int not8(int x) {
  assert((x >= 0) && (x <= _MASK_8));
  return (~x & _MASK_8);
}

int crotl8(int x, int n) => rotl8(clip8(x), n);
int rotl8(int x, int n) {
  assert(n >= 0);
  assert((x >= 0) && (x <= _MASK_8));
  n &= _MASK_3;
  return ((x << n) & _MASK_8) | (x >> (8 - n));
}

int crotr8(int x, int n) => rotr8(clip8(x), n);
int rotr8(int x, int n) {
  assert(n >= 0);
  assert((x >= 0) && (x <= _MASK_8));
  n &= _MASK_3;
  return ((x >> n) & _MASK_8) | ((x << (8 - n)) & _MASK_8);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// 16 bit operations
//
int clip16(int x) => (x & _MASK_16);

/// Packs a 16 bit integer into a byte buffer. The [out] parameter can be an [Uint8List] or a
/// [ByteData] if you will run it several times against the same buffer and want faster execution.
void pack16(int x, dynamic out, int offset, Endian endian) {
  assert((x >= 0) && (x <= _MASK_16));
  if (out is! ByteData) {
    out = ByteData.view(out.buffer, out.offsetInBytes, out.length);
  }
  (out as ByteData).setUint16(offset, x, endian);
}

/// Unpacks a 16 bit integer from a byte buffer. The [inp] parameter can be an [Uint8List] or a
/// [ByteData] if you will run it several times against the same buffer and want faster execution.
int unpack16(dynamic inp, int offset, Endian endian) {
  if (inp is! ByteData) {
    inp = ByteData.view(
        inp.buffer as ByteBuffer, inp.offsetInBytes as int, inp.length as int);
  }
  return (inp as ByteData).getUint16(offset, endian);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// 32 bit operations
//
int clip32(int x) => (x & _MASK_32);

int csum32(int x, int y) => sum32(clip32(x), clip32(y));
int sum32(int x, int y) {
  assert((x >= 0) && (x <= _MASK_32));
  assert((y >= 0) && (y <= _MASK_32));
  return ((x + y) & _MASK_32);
}

int csub32(int x, int y) => sub32(clip32(x), clip32(y));
int sub32(int x, int y) {
  assert((x >= 0) && (x <= _MASK_32));
  assert((y >= 0) && (y <= _MASK_32));
  return ((x - y) & _MASK_32);
}

int cshiftl32(int x, int n) => shiftl32(clip32(x), n);
int shiftl32(int x, int n) {
  assert((x >= 0) && (x <= _MASK_32));
  n &= _MASK_5;
  x &= _MASK32_HI_BITS[n];
  return ((x << n) & _MASK_32);
}

int cshiftr32(int x, int n) => shiftr32(clip32(x), n);
int shiftr32(int x, int n) {
  assert((x >= 0) && (x <= _MASK_32));
  n &= _MASK_5;
  return (x >> n);
}

int cneg32(int x) => neg32(clip32(x));
int neg32(int x) {
  assert((x >= 0) && (x <= _MASK_32));
  return (-x & _MASK_32);
}

int cnot32(int x) => not32(clip32(x));
int not32(int x) {
  assert((x >= 0) && (x <= _MASK_32));
  return (~x & _MASK_32);
}

int crotl32(int x, int n) => rotl32(clip32(x), n);
int rotl32(int x, int n) {
  assert(n >= 0);
  assert((x >= 0) && (x <= _MASK_32));
  n &= _MASK_5;
  return shiftl32(x, n) | (x >> (32 - n));
}

int crotr32(int x, int n) => rotr32(clip32(x), n);
int rotr32(int x, int n) {
  assert(n >= 0);
  assert((x >= 0) && (x <= _MASK_32));
  n &= _MASK_5;
  return (x >> n) | shiftl32(x, (32 - n));
}

/// Packs a 32 bit integer into a byte buffer. The [out] parameter can be an [Uint8List] or a
/// [ByteData] if you will run it several times against the same buffer and want faster execution.
void pack32(int x, dynamic out, int offset, Endian endian) {
  assert((x >= 0) && (x <= _MASK_32));
  if (out is! ByteData) {
    out =
        ByteData.view(out.buffer as ByteBuffer, out.offsetInBytes, out.length);
  }
  (out as ByteData).setUint32(offset, x, endian);
}

/// Unpacks a 32 bit integer from a byte buffer. The [inp] parameter can be an [Uint8List] or a
/// [ByteData] if you will run it several times against the same buffer and want faster execution.
int unpack32(dynamic inp, int offset, Endian endian) {
  if (inp is! ByteData) {
    inp = ByteData.view(inp.buffer, inp.offsetInBytes, inp.length);
  }
  return (inp as ByteData).getUint32(offset, endian);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// 64 bit operations
//
class Register64 {
  static final Register64 _maxValue = Register64(0xFFFFFFFF, 0xFFFFFFFF);

  int _hi32;
  int _lo32;

  Register64([dynamic hiOrLo32OrY = 0, int lo32]) {
    set(hiOrLo32OrY, lo32);
  }

  int get lo32 => _lo32;
  int get hi32 => _hi32;

  @override
  bool operator ==(Object y) =>
      y is Register64 ? (((_hi32 == y._hi32) && (_lo32 == y._lo32))) : false;
  bool operator <(Register64 y) =>
      ((_hi32 < y._hi32) || ((_hi32 == y._hi32) && (_lo32 < y._lo32)));
  bool operator <=(Register64 y) => ((this < y) || (this == y));
  bool operator >(Register64 y) =>
      ((_hi32 > y._hi32) || ((_hi32 == y._hi32) && (_lo32 > y._lo32)));
  bool operator >=(Register64 y) => ((this > y) || (this == y));

  void set(dynamic hiOrLo32OrY, [int lo32]) {
    if (lo32 == null) {
      if (hiOrLo32OrY is Register64) {
        _hi32 = hiOrLo32OrY._hi32;
        _lo32 = hiOrLo32OrY._lo32;
      } else {
        assert(hiOrLo32OrY <= _MASK_32);
        _hi32 = 0;
        _lo32 = hiOrLo32OrY;
      }
    } else {
      assert(hiOrLo32OrY <= _MASK_32);
      assert(lo32 <= _MASK_32);
      _hi32 = hiOrLo32OrY;
      _lo32 = lo32;
    }
  }

  void sum(dynamic y) {
    if (y is int) {
      y &= _MASK_32;
      int slo32 = (_lo32 + y);
      _lo32 = (slo32 & _MASK_32);
      if (slo32 != _lo32) {
        _hi32++;
        _hi32 &= _MASK_32;
      }
    } else {
      int slo32 = (_lo32 + y._lo32);
      _lo32 = (slo32 & _MASK_32);
      var carry = ((slo32 != _lo32) ? 1 : 0);
      _hi32 = (((_hi32 + y._hi32 + carry) as int) & _MASK_32);
    }
  }

  void sumReg(Register64 y) {
    var slo32 = (_lo32 + y._lo32);
    _lo32 = (slo32 & _MASK_32);
    var carry = ((slo32 != _lo32) ? 1 : 0);
    _hi32 = ((_hi32 + y._hi32 + carry) & _MASK_32);
  }

  void sub(dynamic y) {
    // TODO: optimize sub() ???
    sum(Register64(y)..neg());
  }

  void mul(dynamic y) {
    if (y is int) {
      final lo32 = _lo32 * y;
      final carry = (lo32 ~/
          0x100000000); // TODO: use shift right when bug 17715 is fixed
      final hi32 = clip32(_hi32 * y) + carry;

      _hi32 = clip32(hi32);
      _lo32 = clip32(lo32);
    } else {
      final lo32 = _lo32 * y._lo32;
      final carry = (lo32 ~/
          0x100000000); // TODO: use shift right when bug 17715 is fixed
      final hi32 = clip32(_hi32 * y._lo32) + clip32(_lo32 * y._hi32) + carry;

      _hi32 = clip32(hi32);
      _lo32 = clip32(lo32);
    }
  }

  void neg() {
    not();
    sum(1);
  }

  void not() {
    _hi32 = (~_hi32 & _MASK_32);
    _lo32 = (~_lo32 & _MASK_32);
  }

  void and(Register64 y) {
    _hi32 &= y._hi32;
    _lo32 &= y._lo32;
  }

  void or(Register64 y) {
    _hi32 |= y._hi32;
    _lo32 |= y._lo32;
  }

  void xor(Register64 y) {
    _hi32 ^= y._hi32;
    _lo32 ^= y._lo32;
  }

  void shiftl(int n) {
    n &= _MASK_6;
    if (n == 0) {
      // do nothing
    } else if (n >= 32) {
      _hi32 = shiftl32(_lo32, (n - 32));
      _lo32 = 0;
    } else {
      _hi32 = shiftl32(_hi32, n);
      _hi32 |= _lo32 >> (32 - n);
      _lo32 = shiftl32(_lo32, n);
    }
  }

  void shiftr(int n) {
    n &= _MASK_6;
    if (n == 0) {
      // do nothing
    } else if (n >= 32) {
      _lo32 = _hi32 >> (n - 32);
      _hi32 = 0;
    } else {
      _lo32 = _lo32 >> n;
      _lo32 |= shiftl32(_hi32, 32 - n);
      _hi32 = _hi32 >> n;
    }
  }

  void rotl(int n) {
    n &= _MASK_6;
    if (n == 0) {
      // do nothing
    } else {
      if (n >= 32) {
        var swap = _hi32;
        _hi32 = _lo32;
        _lo32 = swap;
        n -= 32;
      }

      if (n == 0) {
        // do nothing
      } else {
        var hi32 = _hi32;
        _hi32 = shiftl32(_hi32, n);
        _hi32 |= _lo32 >> (32 - n);
        _lo32 = shiftl32(_lo32, n);
        _lo32 |= hi32 >> (32 - n);
      }
    }
  }

  void rotr(int n) {
    n &= _MASK_6;
    if (n == 0) {
      // do nothing
    } else {
      if (n >= 32) {
        var swap = _hi32;
        _hi32 = _lo32;
        _lo32 = swap;
        n -= 32;
      }

      if (n == 0) {
        // do nothing
      } else {
        var hi32 = _hi32;
        _hi32 = _hi32 >> n;
        _hi32 |= shiftl32(_lo32, (32 - n));
        _lo32 = _lo32 >> n;
        _lo32 |= shiftl32(hi32, (32 - n));
      }
    }
  }

  /// Packs a 64 bit integer into a byte buffer. The [out] parameter can be an [Uint8List] or a
  /// [ByteData] if you will run it several times against the same buffer and want faster execution.
  void pack(dynamic out, int offset, Endian endian) {
    switch (endian) {
      case Endian.big:
        pack32(hi32, out, offset, endian);
        pack32(lo32, out, offset + 4, endian);
        break;

      case Endian.little:
        pack32(hi32, out, offset + 4, endian);
        pack32(lo32, out, offset, endian);
        break;

      default:
        throw UnsupportedError('Invalid endianness: $endian');
    }
  }

  /// Unpacks a 64 bit integer from a byte buffer. The [inp] parameter can be an [Uint8List] or a
  /// [ByteData] if you will run it several times against the same buffer and want faster execution.
  void unpack(dynamic inp, int offset, Endian endian) {
    switch (endian) {
      case Endian.big:
        _hi32 = unpack32(inp, offset, endian);
        _lo32 = unpack32(inp, offset + 4, endian);
        break;

      case Endian.little:
        _hi32 = unpack32(inp, offset + 4, endian);
        _lo32 = unpack32(inp, offset, endian);
        break;

      default:
        throw UnsupportedError('Invalid endianness: $endian');
    }
  }

  @override
  String toString() {
    var sb = StringBuffer();
    _padWrite(sb, _hi32);
    _padWrite(sb, _lo32);
    return sb.toString();
  }

  void _padWrite(StringBuffer sb, int value) {
    var str = value.toRadixString(16);
    for (var i = (8 - str.length); i > 0; i--) {
      sb.write('0');
    }
    sb.write(str);
  }

  @override
  // TODO: implement hashCode
  int get hashCode => super.hashCode;
}

class Register64List {
  final List<Register64> _list;

  Register64List.from(List<List<int>> values)
      : _list = List<Register64>.generate(
            values.length, (i) => Register64(values[i][0], values[i][1]));

  Register64List(int length)
      : _list = List<Register64>.generate(length, (_) => Register64());

  int get length => _list.length;

  Register64 operator [](int index) => _list[index];

  void fillRange(int start, int end, dynamic hiOrLo32OrY, [int lo32]) {
    for (var i = start; i < end; i++) {
      _list[i].set(hiOrLo32OrY, lo32);
    }
  }

  void setRange(int start, int end, Register64List list, [int skipCount = 0]) {
    var length = end - start;
    for (var i = 0; i < length; i++) {
      _list[start + i].set(list[skipCount + i]);
    }
  }

  @override
  String toString() {
    var sb = StringBuffer('(');
    for (var i = 0; i < _list.length; i++) {
      if (i > 0) {
        sb.write(', ');
      }
      sb.write(_list[i].toString());
    }
    sb.write(')');
    return sb.toString();
  }
}
