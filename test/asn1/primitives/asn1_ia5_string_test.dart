import 'dart:typed_data';

import 'package:pointycastle/asn1/primitives/asn1_ia5_string.dart';
import 'package:test/test.dart';

void main() {
  test('Test named constructor fromBytes', () {
    var bytes = Uint8List.fromList([
      0x16,
      0x1C,
      0x68,
      0x74,
      0x74,
      0x70,
      0x73,
      0x3A,
      0x2F,
      0x2F,
      0x77,
      0x77,
      0x77,
      0x2E,
      0x64,
      0x69,
      0x67,
      0x69,
      0x63,
      0x65,
      0x72,
      0x74,
      0x2E,
      0x63,
      0x6F,
      0x6D,
      0x2F,
      0x43,
      0x50,
      0x53
    ]);

    var valueBytes = Uint8List.fromList([
      0x68,
      0x74,
      0x74,
      0x70,
      0x73,
      0x3A,
      0x2F,
      0x2F,
      0x77,
      0x77,
      0x77,
      0x2E,
      0x64,
      0x69,
      0x67,
      0x69,
      0x63,
      0x65,
      0x72,
      0x74,
      0x2E,
      0x63,
      0x6F,
      0x6D,
      0x2F,
      0x43,
      0x50,
      0x53
    ]);

    var asn1Object = ASN1IA5String.fromBytes(bytes);
    expect(asn1Object.tag, 22);
    expect(asn1Object.encodedBytes, bytes);
    expect(asn1Object.valueByteLength, 28);
    expect(asn1Object.valueStartPosition, 2);
    expect(asn1Object.stringValue, 'https://www.digicert.com/CPS');
    expect(asn1Object.valueBytes, valueBytes);
  });

  test('Test encode', () {
    var asn1Object = ASN1IA5String('https://www.digicert.com/CPS');

    var bytes = Uint8List.fromList([
      0x16,
      0x1C,
      0x68,
      0x74,
      0x74,
      0x70,
      0x73,
      0x3A,
      0x2F,
      0x2F,
      0x77,
      0x77,
      0x77,
      0x2E,
      0x64,
      0x69,
      0x67,
      0x69,
      0x63,
      0x65,
      0x72,
      0x74,
      0x2E,
      0x63,
      0x6F,
      0x6D,
      0x2F,
      0x43,
      0x50,
      0x53
    ]);

    expect(asn1Object.encode(), bytes);
  });
}
