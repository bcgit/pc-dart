import 'dart:typed_data';

import 'package:pointycastle/asn1/primitives/asn1_object_identifier.dart';
import 'package:test/test.dart';

void main() {
  test('Test named constructor fromBytes', () {
    var bytes = Uint8List.fromList([0x06, 0x03, 0x55, 0x04, 0x03]);

    var valueBytes = Uint8List.fromList([0x55, 0x04, 0x03]);

    var asn1Object = ASN1ObjectIdentifier.fromBytes(bytes);
    expect(asn1Object.tag, 6);
    expect(asn1Object.encodedBytes, bytes);
    expect(asn1Object.valueByteLength, 3);
    expect(asn1Object.valueStartPosition, 2);
    expect(asn1Object.valueBytes, valueBytes);
    expect(asn1Object.objectIdentifier.length, 4);
    expect(asn1Object.objectIdentifier.elementAt(0), 2);
    expect(asn1Object.objectIdentifier.elementAt(1), 5);
    expect(asn1Object.objectIdentifier.elementAt(2), 4);
    expect(asn1Object.objectIdentifier.elementAt(3), 3);
    expect(asn1Object.objectIdentifierAsString, '2.5.4.3');
  });

  test('Test encode', () {
    var oiBytes = Uint8List.fromList([2, 5, 4, 3]);
    var asn1Object = ASN1ObjectIdentifier(oiBytes);

    var bytes = Uint8List.fromList([0x06, 0x03, 0x55, 0x04, 0x03]);

    expect(asn1Object.encode(), bytes);
  });

  test('Test named constructor fromComponentString', () {
    var bytes = Uint8List.fromList([0x06, 0x03, 0x55, 0x04, 0x03]);

    var valueBytes = Uint8List.fromList([0x55, 0x04, 0x03]);

    var asn1Object = ASN1ObjectIdentifier.fromComponentString('2.5.4.3');
    expect(asn1Object.tag, 6);
    expect(asn1Object.encode(), bytes);
    expect(asn1Object.valueByteLength, 3);
    expect(asn1Object.valueStartPosition, 2);
    expect(asn1Object.valueBytes, valueBytes);
    expect(asn1Object.objectIdentifier.length, 4);
    expect(asn1Object.objectIdentifier.elementAt(0), 2);
    expect(asn1Object.objectIdentifier.elementAt(1), 5);
    expect(asn1Object.objectIdentifier.elementAt(2), 4);
    expect(asn1Object.objectIdentifier.elementAt(3), 3);
    expect(asn1Object.objectIdentifierAsString, '2.5.4.3');
  });
}
