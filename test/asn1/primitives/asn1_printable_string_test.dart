import 'dart:typed_data';

import 'package:pointycastle/asn1/primitives/asn1_printable_string.dart';
import 'package:test/test.dart';

void main() {
  test('Test named constructor fromBytes', () {
    var bytes = Uint8List.fromList([
      0x13,
      0x02,
      0x55,
      0x53,
    ]);

    var valueBytes = Uint8List.fromList([
      0x55,
      0x53,
    ]);

    var asn1Object = ASN1PrintableString.fromBytes(bytes);
    expect(asn1Object.tag, 19);
    expect(asn1Object.encodedBytes, bytes);
    expect(asn1Object.valueByteLength, 2);
    expect(asn1Object.valueStartPosition, 2);
    expect(asn1Object.stringValue, 'US');
    expect(asn1Object.valueBytes, valueBytes);
  });

  test('Test encode', () {
    var asn1Object = ASN1PrintableString('US');

    var bytes = Uint8List.fromList([
      0x13,
      0x02,
      0x55,
      0x53,
    ]);

    expect(asn1Object.encode(), bytes);
  });
}
