// See file LICENSE for more information.

library pointycastle.src.utils;

import "dart:typed_data";

void arrayCopy(Uint8List sourceArr, int sourcePos, Uint8List outArr, int outPos,
    int len) {
  for (int i = 0; i < len; i++) {
    outArr[outPos + i] = sourceArr[sourcePos + i];
  }
}

/// Decode a BigInt from bytes in big-endian encoding.
BigInt decodeBigInt(List<int> bytes) {
  BigInt result = new BigInt.from(0);
  for (int i = 0; i < bytes.length; i++) {
    result += new BigInt.from(bytes[bytes.length - i - 1]) << (8 * i);
  }
  return result;
}

var _byteMask = new BigInt.from(0xff);

/// Encode a BigInt into bytes using big-endian encoding.
Uint8List encodeBigInt(BigInt number) {
  // Not handling negative numbers. Decide how you want to do that.
  int size = (number.bitLength + 7) >> 3;
  var result = new Uint8List(size);
  for (int i = 0; i < size; i++) {
    result[size - i - 1] = (number & _byteMask).toInt();
    number = number >> 8;
  }
  return result;
}
