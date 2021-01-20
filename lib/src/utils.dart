// See file LICENSE for more information.

library src.utils;

import 'dart:typed_data';

void arrayCopy(Uint8List? sourceArr, int sourcePos, Uint8List? outArr,
    int outPos, int len) {
  for (var i = 0; i < len; i++) {
    outArr![outPos + i] = sourceArr![sourcePos + i];
  }
}

Uint8List concatUint8List(Iterable<Uint8List> list) =>
    Uint8List.fromList(list.expand((element) => element).toList());

/// Decode a BigInt from bytes in big-endian encoding.
/// Twos compliment.
BigInt decodeBigInt(List<int> bytes) {
  var negative = bytes.isNotEmpty && bytes[0] & 0x80 == 0x80;

  BigInt result;

  if (bytes.length == 1) {
    result = BigInt.from(bytes[0]);
  } else {
    result = BigInt.zero;
    for (var i = 0; i < bytes.length; i++) {
      var item = bytes[bytes.length - i - 1];
      result |= (BigInt.from(item) << (8 * i));
    }
  }
  return result != BigInt.zero
      ? negative
          ? result.toSigned(result.bitLength)
          : result
      : BigInt.zero;
}

/// Decode a big integer with arbitrary sign.
/// When:
/// sign == 0: Zero regardless of magnitude
/// sign < 0: Negative
/// sign > 0: Positive
BigInt decodeBigIntWithSign(int sign, List<int> magnitude) {
  if (sign == 0) {
    return BigInt.zero;
  }

  BigInt result;

  if (magnitude.length == 1) {
    result = BigInt.from(magnitude[0]);
  } else {
    result = BigInt.from(0);
    for (var i = 0; i < magnitude.length; i++) {
      var item = magnitude[magnitude.length - i - 1];
      result |= (BigInt.from(item) << (8 * i));
    }
  }

  if (result != BigInt.zero) {
    if (sign < 0) {
      result = result.toSigned(result.bitLength);
    } else {
      result = result.toUnsigned(result.bitLength);
    }
  }
  return result;
}

var _byteMask = BigInt.from(0xff);
final negativeFlag = BigInt.from(0x80);

/// Encode a BigInt into bytes using big-endian encoding.
/// It encodes the integer to a minimal twos-compliment integer as defined by
/// ASN.1
Uint8List encodeBigInt(BigInt? number) {
  if (number == BigInt.zero) {
    return Uint8List.fromList([0]);
  }

  int needsPaddingByte;
  int rawSize;

  if (number! > BigInt.zero) {
    rawSize = (number.bitLength + 7) >> 3;
    needsPaddingByte =
        ((number >> (rawSize - 1) * 8) & negativeFlag) == negativeFlag ? 1 : 0;
  } else {
    needsPaddingByte = 0;
    rawSize = (number.bitLength + 8) >> 3;
  }

  final size = rawSize + needsPaddingByte;
  var result = Uint8List(size);
  for (var i = 0; i < rawSize; i++) {
    result[size - i - 1] = (number! & _byteMask).toInt();
    number = number >> 8;
  }
  return result;
}

/// Encode as Big Endian unsigned byte array.
Uint8List encodeBigIntAsUnsigned(BigInt number) {
  if (number == BigInt.zero) {
    return Uint8List.fromList([0]);
  }
  var size = number.bitLength + (number.isNegative ? 8 : 7) >> 3;
  var result = Uint8List(size);
  for (var i = 0; i < size; i++) {
    result[size - i - 1] = (number & _byteMask).toInt();
    number = number >> 8;
  }
  return result;
}

bool constantTimeAreEqual(Uint8List expected, Uint8List supplied) {
  if (expected == supplied) {
    return true;
  }

  var len =
      (expected.length < supplied.length) ? expected.length : supplied.length;

  var nonEqual = expected.length ^ supplied.length;

  for (var i = 0; i != len; i++) {
    nonEqual |= (expected[i] ^ supplied[i]);
  }
  for (var i = len; i < supplied.length; i++) {
    nonEqual |= (supplied[i] ^ ~supplied[i]);
  }

  return nonEqual == 0;
}

bool constantTimeAreEqualOffset(
    int len, Uint8List a, int aOff, Uint8List b, int bOff) {
  if (len < 0) {
    throw ArgumentError('"len" cannot be negative');
  }
  if (aOff > (a.length - len)) {
    throw ArgumentError('"aOff" value invalid for specified length');
  }
  if (bOff > (b.length - len)) {
    throw ArgumentError('"bOff" value invalid for specified length');
  }

  var d = 0;
  for (var i = 0; i < len; ++i) {
    d |= (a[aOff + i] ^ b[bOff + i]);
  }
  return 0 == d;
}
