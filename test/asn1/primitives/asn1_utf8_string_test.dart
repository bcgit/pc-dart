import 'dart:typed_data';

import 'package:pointycastle/asn1/primitives/asn1_utf8_string.dart';
import 'package:test/test.dart';

void main() {
  test('Test named constructor fromBytes', () {
    var bytes = Uint8List.fromList([
      0x0C,
      0x0B,
      0x48,
      0x65,
      0x6C,
      0x6C,
      0x6F,
      0x20,
      0x57,
      0x6F,
      0x72,
      0x6C,
      0x64
    ]);

    var valueBytes = Uint8List.fromList(
        [0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64]);

    var asn1Object = ASN1UTF8String.fromBytes(bytes);
    expect(asn1Object.tag, 12);
    expect(asn1Object.encodedBytes, bytes);
    expect(asn1Object.valueByteLength, 11);
    expect(asn1Object.valueStartPosition, 2);
    expect(asn1Object.valueBytes, valueBytes);
    expect(asn1Object.utf8StringValue, 'Hello World');
  });

  test('Test encode', () {
    var utf8String = ASN1UTF8String('Hello World');

    var bytes = Uint8List.fromList([
      0x0C,
      0x0B,
      0x48,
      0x65,
      0x6C,
      0x6C,
      0x6F,
      0x20,
      0x57,
      0x6F,
      0x72,
      0x6C,
      0x64
    ]);

    expect(utf8String.encode(), bytes);
  });
}
