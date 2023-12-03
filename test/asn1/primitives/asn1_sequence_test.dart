import 'dart:typed_data';

import 'package:pointycastle/asn1/primitives/asn1_ia5_string.dart';
import 'package:pointycastle/asn1/primitives/asn1_integer.dart';
import 'package:pointycastle/asn1/primitives/asn1_null.dart';
import 'package:pointycastle/asn1/primitives/asn1_object_identifier.dart';
import 'package:pointycastle/asn1/primitives/asn1_sequence.dart';
import 'package:test/test.dart';

void main() {
  test('Test named constructor fromBytes', () {
    /*
    SEQUENCE (2 elem)
      OBJECT IDENTIFIER 1.2.840.113549.1.1.11 sha256WithRSAEncryption (PKCS #1)
      NULL
    */
    var bytes = Uint8List.fromList([
      0x30,
      0x0D,
      0x06,
      0x09,
      0x2A,
      0x86,
      0x48,
      0x86,
      0xF7,
      0x0D,
      0x01,
      0x01,
      0x0B,
      0x05,
      0x00
    ]);

    var valueBytes = Uint8List.fromList([
      0x06,
      0x09,
      0x2A,
      0x86,
      0x48,
      0x86,
      0xF7,
      0x0D,
      0x01,
      0x01,
      0x0B,
      0x05,
      0x00
    ]);

    var asn1Object = ASN1Sequence.fromBytes(bytes);
    expect(asn1Object.tag, 48);
    expect(asn1Object.isConstructed, true);
    expect(asn1Object.encodedBytes, bytes);
    expect(asn1Object.valueByteLength, 13);
    expect(asn1Object.valueStartPosition, 2);
    expect(asn1Object.valueBytes, valueBytes);
    expect(asn1Object.elements!.length, 2);
    expect(asn1Object.elements!.elementAt(0) is ASN1ObjectIdentifier, true);
    expect(asn1Object.elements!.elementAt(1) is ASN1Null, true);
  });

  test('Test named constructor fromBytes with nested indefinite length', () {
    /*
    SEQUENCE (3 elem, indefinite length)
      INTEGER 1
      SEQUENCE (1 elem, indefinite length)
        OBJECT IDENTIFIER 1.2.840.113549.1.7.1 data (PKCS #7)
      INTEGER 1
    */
    var bytes = Uint8List.fromList([
      0x30,
      0x80,
      0x02,
      0x01,
      0x01,
      0x30,
      0x80,
      0x06,
      0x09,
      0x2A,
      0x86,
      0x48,
      0x86,
      0xF7,
      0x0D,
      0x01,
      0x07,
      0x01,
      0x00,
      0x00,
      0x02,
      0x01,
      0x01,
      0x00,
      0x00
    ]);

    var valueBytes = Uint8List.fromList([
      0x02,
      0x01,
      0x01,
      0x30,
      0x80,
      0x06,
      0x09,
      0x2A,
      0x86,
      0x48,
      0x86,
      0xF7,
      0x0D,
      0x01,
      0x07,
      0x01,
      0x00,
      0x00,
      0x02,
      0x01,
      0x01,
    ]);

    var innerSequenceBytes = Uint8List.fromList([
      0x30,
      0x80,
      0x06,
      0x09,
      0x2A,
      0x86,
      0x48,
      0x86,
      0xF7,
      0x0D,
      0x01,
      0x07,
      0x01,
      0x00,
      0x00
    ]);

    var innerSequenceValueBytes = Uint8List.fromList(
        [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01]);

    var asn1Object = ASN1Sequence.fromBytes(bytes);
    expect(asn1Object.tag, 48);
    expect(asn1Object.isConstructed, true);
    expect(asn1Object.encodedBytes, bytes);
    expect(asn1Object.valueByteLength, 21);
    expect(asn1Object.valueStartPosition, 2);
    expect(asn1Object.valueBytes, valueBytes);
    expect(asn1Object.elements!.length, 3);
    expect(asn1Object.elements!.elementAt(0) is ASN1Integer, true);
    expect(asn1Object.elements!.elementAt(1) is ASN1Sequence, true);
    expect(asn1Object.elements!.elementAt(2) is ASN1Integer, true);

    final innerSequence = asn1Object.elements!.elementAt(1) as ASN1Sequence;
    expect(innerSequence.tag, 48);
    expect(innerSequence.isConstructed, true);
    expect(innerSequence.encodedBytes, innerSequenceBytes);
    expect(innerSequence.valueByteLength, 11);
    expect(innerSequence.valueStartPosition, 2);
    expect(innerSequence.valueBytes, innerSequenceValueBytes);
  });

  test('Test encode', () {
    // Test encoding with zero elements given
    var asn1Object = ASN1Sequence(elements: []);

    var bytes = Uint8List.fromList([
      0x30,
      0x00,
    ]);

    expect(asn1Object.encode(), bytes);

    // Test encoding with null given
    asn1Object = ASN1Sequence();

    bytes = Uint8List.fromList([
      0x30,
      0x00,
    ]);

    expect(asn1Object.encode(), bytes);

    var e1 = ASN1IA5String(stringValue: 'test1');

    var e2 = ASN1IA5String(stringValue: '@');

    var e3 = ASN1IA5String(stringValue: 'rsa.com');

    asn1Object = ASN1Sequence(elements: [e1, e2, e3]);

    bytes = Uint8List.fromList([
      0x30,
      0x13,
      0x16,
      0x05,
      0x74,
      0x65,
      0x73,
      0x74,
      0x31,
      0x16,
      0x01,
      0x40,
      0x16,
      0x07,
      0x72,
      0x73,
      0x61,
      0x2e,
      0x63,
      0x6f,
      0x6d
    ]);

    expect(asn1Object.encode(), bytes);

    asn1Object = ASN1Sequence();
    asn1Object.add(e1);
    asn1Object.add(e2);
    asn1Object.add(e3);

    expect(asn1Object.encode(), bytes);
  });

  test('Test dump', () {
    var expected = '''SEQUENCE (2 elem)
  OBJECT IDENTIFIER 1.2.840.113549.1.1.11 sha256WithRSAEncryption
  NULL''';
    var bytes = Uint8List.fromList([
      0x30,
      0x0D,
      0x06,
      0x09,
      0x2A,
      0x86,
      0x48,
      0x86,
      0xF7,
      0x0D,
      0x01,
      0x01,
      0x0B,
      0x05,
      0x00
    ]);

    var asn1Object = ASN1Sequence.fromBytes(bytes);
    expect(expected, asn1Object.dump());
  });
}
