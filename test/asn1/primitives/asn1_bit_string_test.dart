import 'dart:typed_data';

import 'package:pointycastle/asn1/asn1_encoding_rule.dart';
import 'package:pointycastle/asn1/asn1_tags.dart';
import 'package:pointycastle/asn1/primitives/asn1_bit_string.dart';

import 'package:test/test.dart';

void main() {
  test('Test decode DER', () {
    var bytes = Uint8List.fromList([0x03, 0x02, 0x05, 0xA0]);

    var valueBytes = Uint8List.fromList([0x05, 0xA0]);

    var asn1Object = ASN1BitString.fromBytes(bytes);
    expect(asn1Object.tag, 3);
    expect(asn1Object.isConstructed, false);
    expect(asn1Object.encodedBytes, bytes);
    expect(asn1Object.valueByteLength, 2);
    expect(asn1Object.valueStartPosition, 2);
    expect(asn1Object.valueBytes, valueBytes);
  });

  test('Test decode DER with unused bit', () {
    var bytes = Uint8List.fromList([0x03, 0x03, 0x00, 0x05, 0xA0]);

    var valueBytes = Uint8List.fromList([0x00, 0x05, 0xA0]);

    var asn1Object = ASN1BitString.fromBytes(bytes);
    expect(asn1Object.tag, 3);
    expect(asn1Object.isConstructed, false);
    expect(asn1Object.encodedBytes, bytes);
    expect(asn1Object.valueByteLength, 3);
    expect(asn1Object.valueStartPosition, 2);
    expect(asn1Object.valueBytes, valueBytes);
  });

  test('Test decode BER Long Form Length', () {
    var bytes = Uint8List.fromList([0x03, 0x81, 0x04, 0x06, 0x6e, 0x5d, 0xc0]);

    var valueBytes = Uint8List.fromList([0x06, 0x6e, 0x5d, 0xc0]);

    var asn1Object = ASN1BitString.fromBytes(bytes);
    expect(asn1Object.tag, 3);
    expect(asn1Object.isConstructed, false);
    expect(asn1Object.encodedBytes, bytes);
    expect(asn1Object.valueByteLength, 4);
    expect(asn1Object.valueStartPosition, 3);
    expect(asn1Object.valueBytes, valueBytes);
  });

  test('Test decode BER Padded', () {
    var bytes = Uint8List.fromList([0x03, 0x81, 0x04, 0x06, 0x6e, 0x5d, 0xe0]);

    var valueBytes = Uint8List.fromList([0x06, 0x6e, 0x5d, 0xe0]);

    var asn1Object = ASN1BitString.fromBytes(bytes);
    expect(asn1Object.tag, 3);
    expect(asn1Object.isConstructed, false);
    expect(asn1Object.encodedBytes, bytes);
    expect(asn1Object.valueByteLength, 4);
    expect(asn1Object.valueStartPosition, 3);
    expect(asn1Object.valueBytes, valueBytes);
  });

  test('Test decode BER Constructed', () {
    var bytes = Uint8List.fromList(
        [0x23, 0x09, 0x03, 0x03, 0x00, 0x6e, 0x5d, 0x03, 0x02, 0x06, 0xc0]);

    var valueBytes = Uint8List.fromList(
        [0x03, 0x03, 0x00, 0x6e, 0x5d, 0x03, 0x02, 0x06, 0xc0]);

    var asn1Object = ASN1BitString.fromBytes(bytes);
    expect(asn1Object.tag, 35);
    expect(asn1Object.isConstructed, true);
    expect(asn1Object.encodedBytes, bytes);
    expect(asn1Object.valueByteLength, 9);
    expect(asn1Object.valueStartPosition, 2);
    expect(asn1Object.elements.length, 2);
    expect(asn1Object.valueBytes, valueBytes);
  });

  test('Test decode BER Constructed Indefinite Length', () {
    var bytes = Uint8List.fromList([
      0x23,
      0x80,
      0x03,
      0x03,
      0x00,
      0x6e,
      0x5d,
      0x03,
      0x02,
      0x06,
      0xc0,
      0x00,
      0x00
    ]);

    var valueBytes = Uint8List.fromList(
        [0x03, 0x03, 0x00, 0x6e, 0x5d, 0x03, 0x02, 0x06, 0xc0]);

    var asn1Object = ASN1BitString.fromBytes(bytes);
    expect(asn1Object.tag, 35);
    expect(asn1Object.isConstructed, true);
    expect(asn1Object.encodedBytes, bytes);
    expect(asn1Object.valueByteLength, 9);
    expect(asn1Object.valueStartPosition, 2);
    expect(asn1Object.elements.length, 2);
    expect(asn1Object.valueBytes, valueBytes);
  });

  test('Test encode DER', () {
    var asn1BitString = ASN1BitString(stringValues: [0x05, 0xA0]);

    var bytes = Uint8List.fromList([0x03, 0x02, 0x05, 0xA0]);

    expect(asn1BitString.encode(), bytes);
  });

  test('Test encode BER Constructed', () {
    var e1 = ASN1BitString(stringValues: [0x00, 0x6e, 0x5d]);

    var e2 = ASN1BitString(stringValues: [0x06, 0xc0]);

    var asn1Object =
        ASN1BitString(elements: [e1, e2], tag: ASN1Tags.BIT_STRING_CONSTRUCTED);

    var bytes = Uint8List.fromList(
        [0x23, 0x09, 0x03, 0x03, 0x00, 0x6e, 0x5d, 0x03, 0x02, 0x06, 0xc0]);

    expect(
        asn1Object.encode(
            encodingRule: ASN1EncodingRule.ENCODING_BER_CONSTRUCTED),
        bytes);
  });

  test('Test encode BER Long Form Length', () {
    var asn1Object = ASN1BitString(stringValues: [0x06, 0x6e, 0x5d, 0xc0]);

    var bytes = Uint8List.fromList([0x03, 0x81, 0x04, 0x06, 0x6e, 0x5d, 0xc0]);

    expect(
        asn1Object.encode(
            encodingRule: ASN1EncodingRule.ENCODING_BER_LONG_LENGTH_FORM),
        bytes);
  });

  test('Test encode BER Constructed Indefinite Length', () {
    var e1 = ASN1BitString(stringValues: [0x00, 0x6e, 0x5d]);

    var e2 = ASN1BitString(stringValues: [0x06, 0xc0]);

    var asn1Object =
        ASN1BitString(elements: [e1, e2], tag: ASN1Tags.BIT_STRING_CONSTRUCTED);

    var bytes = Uint8List.fromList([
      0x23,
      0x80,
      0x03,
      0x03,
      0x00,
      0x6e,
      0x5d,
      0x03,
      0x02,
      0x06,
      0xc0,
      0x00,
      0x00
    ]);

    expect(
        asn1Object.encode(
            encodingRule:
                ASN1EncodingRule.ENCODING_BER_CONSTRUCTED_INDEFINITE_LENGTH),
        bytes);
  });

  test('Test encode BER Padded', () {
    var asn1Object = ASN1BitString(stringValues: [0x06, 0x6e, 0x5d, 0xe0]);

    var bytes = Uint8List.fromList([0x03, 0x04, 0x06, 0x6e, 0x5d, 0xe0]);

    expect(
        asn1Object.encode(encodingRule: ASN1EncodingRule.ENCODING_BER_PADDED),
        bytes);
  });
}
