import 'dart:typed_data';

import 'package:pointycastle/asn1/primitives/asn1_null.dart';
import 'package:test/test.dart';

void main() {
  test('Test named constructor fromBytes', () {
    var bytes = Uint8List.fromList([0x05, 0x00]);

    var valueBytes = Uint8List.fromList([]);

    var asn1Object = ASN1Null.fromBytes(bytes);
    expect(asn1Object.tag, 5);
    expect(asn1Object.encodedBytes, bytes);
    expect(asn1Object.valueByteLength, 0);
    expect(asn1Object.valueStartPosition, 2);
    expect(asn1Object.valueBytes, valueBytes);
  });

  test('Test encode', () {
    var asn1Null = ASN1Null();

    var bytes = Uint8List.fromList([0x05, 0x00]);

    expect(asn1Null.encode(), bytes);
  });
}
