import 'dart:typed_data';

import 'package:pointycastle/asn1/primitives/asn1_bit_string.dart';

import 'package:test/test.dart';

void main() {
  test('Test named constructor fromBytes', () {
    var bytes = Uint8List.fromList([0x03, 0x02, 0x05, 0xA0]);

    var valueBytes = Uint8List.fromList([0x05, 0xA0]);

    var asn1Object = ASN1BitString.fromBytes(bytes);
    expect(asn1Object.tag, 3);
    expect(asn1Object.encodedBytes, bytes);
    expect(asn1Object.valueByteLength, 2);
    expect(asn1Object.valueStartPosition, 2);
    expect(asn1Object.valueBytes, valueBytes);
  });

  test('Test encode', () {
    var asn1BitString = ASN1BitString([0x05, 0xA0]);

    var bytes = Uint8List.fromList([0x03, 0x02, 0x05, 0xA0]);

    expect(asn1BitString.encode(), bytes);
  });
}
