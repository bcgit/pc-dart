import 'dart:typed_data';

import 'package:pointycastle/asn1/asn1_parser.dart';
import 'package:pointycastle/asn1/primitives/asn1_null.dart';
import 'package:pointycastle/asn1/primitives/asn1_object_identifier.dart';
import 'package:pointycastle/asn1/primitives/asn1_printable_string.dart';
import 'package:pointycastle/asn1/primitives/asn1_sequence.dart';
import 'package:pointycastle/asn1/primitives/asn1_set.dart';
import 'package:test/test.dart';

void main() {
  ///
  /// Test simple structur
  ///
  /// ```
  ///   SEQUENCE (2 elem)
  ///     OBJECT IDENTIFIER 1.2.840.113549.1.1.11 sha256WithRSAEncryption (PKCS #1)
  ///     NULL
  /// ```
  ///
  test('Test nextObject 1', () {
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
    var parser = ASN1Parser(bytes);
    var sequence = parser.nextObject() as ASN1Sequence;
    expect(sequence.encodedBytes.length, sequence.totalEncodedByteLength);
    expect(sequence.elements.length, 2);
    expect(sequence.elements.elementAt(0) is ASN1ObjectIdentifier, true);
    expect(sequence.elements.elementAt(1) is ASN1Null, true);
  });

  ///
  /// Test simple structur
  ///
  /// ```
  /// SEQUENCE (4 elem)
  ///    SET (1 elem)
  ///      SEQUENCE (2 elem)
  ///        OBJECT IDENTIFIER 2.5.4.6 countryName (X.520 DN component)
  ///        PrintableString US
  ///    SET (1 elem)
  ///      SEQUENCE (2 elem)
  ///        OBJECT IDENTIFIER 2.5.4.10 organizationName (X.520 DN component)
  ///        PrintableString DigiCert Inc
  ///    SET (1 elem)
  ///      SEQUENCE (2 elem)
  ///        OBJECT IDENTIFIER 2.5.4.11 organizationalUnitName (X.520 DN component)
  ///        PrintableString www.digicert.com
  ///    SET (1 elem)
  ///      SEQUENCE (2 elem)
  ///        OBJECT IDENTIFIER 2.5.4.3 commonName (X.520 DN component)
  ///        PrintableString Thawte RSA CA 2018
  /// ```
  ///
  test('Test nextObject 2', () {
    var bytes = Uint8List.fromList([
      0x30,
      0x5C,
      0x31,
      0x0B,
      0x30,
      0x09,
      0x06,
      0x03,
      0x55,
      0x04,
      0x06,
      0x13,
      0x02,
      0x55,
      0x53,
      0x31,
      0x15,
      0x30,
      0x13,
      0x06,
      0x03,
      0x55,
      0x04,
      0x0A,
      0x13,
      0x0C,
      0x44,
      0x69,
      0x67,
      0x69,
      0x43,
      0x65,
      0x72,
      0x74,
      0x20,
      0x49,
      0x6E,
      0x63,
      0x31,
      0x19,
      0x30,
      0x17,
      0x06,
      0x03,
      0x55,
      0x04,
      0x0B,
      0x13,
      0x10,
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
      0x31,
      0x1B,
      0x30,
      0x19,
      0x06,
      0x03,
      0x55,
      0x04,
      0x03,
      0x13,
      0x12,
      0x54,
      0x68,
      0x61,
      0x77,
      0x74,
      0x65,
      0x20,
      0x52,
      0x53,
      0x41,
      0x20,
      0x43,
      0x41,
      0x20,
      0x32,
      0x30,
      0x31,
      0x38
    ]);
    var parser = ASN1Parser(bytes);
    var sequence = parser.nextObject() as ASN1Sequence;
    expect(sequence.encodedBytes.length, sequence.totalEncodedByteLength);
    expect(sequence.elements.length, 4);
    expect(sequence.elements.elementAt(0) is ASN1Set, true);
    expect(sequence.elements.elementAt(1) is ASN1Set, true);
    expect(sequence.elements.elementAt(2) is ASN1Set, true);
    expect(sequence.elements.elementAt(3) is ASN1Set, true);

    var set1 = sequence.elements.elementAt(0) as ASN1Set;
    expect(set1.elements.length, 1);
    expect(set1.elements.elementAt(0) is ASN1Sequence, true);

    var seq1 = set1.elements.elementAt(0) as ASN1Sequence;
    expect(seq1.elements.length, 2);
    expect(seq1.elements.elementAt(0) is ASN1ObjectIdentifier, true);
    expect(seq1.elements.elementAt(1) is ASN1PrintableString, true);
    var oi1 = seq1.elements.elementAt(0) as ASN1ObjectIdentifier;
    var string1 = seq1.elements.elementAt(1) as ASN1PrintableString;
    expect(oi1.objectIdentifierAsString, '2.5.4.6');
    expect(string1.stringValue, 'US');

    var set2 = sequence.elements.elementAt(1) as ASN1Set;
    expect(set2.elements.length, 1);
    expect(set2.elements.elementAt(0) is ASN1Sequence, true);

    var seq2 = set2.elements.elementAt(0) as ASN1Sequence;
    expect(seq2.elements.length, 2);
    expect(seq2.elements.elementAt(0) is ASN1ObjectIdentifier, true);
    expect(seq2.elements.elementAt(1) is ASN1PrintableString, true);
    var oi2 = seq2.elements.elementAt(0) as ASN1ObjectIdentifier;
    var string2 = seq2.elements.elementAt(1) as ASN1PrintableString;
    expect(oi2.objectIdentifierAsString, '2.5.4.10');
    expect(string2.stringValue, 'DigiCert Inc');

    var set3 = sequence.elements.elementAt(2) as ASN1Set;
    expect(set3.elements.length, 1);
    expect(set3.elements.elementAt(0) is ASN1Sequence, true);

    var seq3 = set3.elements.elementAt(0) as ASN1Sequence;
    expect(seq3.elements.length, 2);
    expect(seq3.elements.elementAt(0) is ASN1ObjectIdentifier, true);
    expect(seq3.elements.elementAt(1) is ASN1PrintableString, true);
    var oi3 = seq3.elements.elementAt(0) as ASN1ObjectIdentifier;
    var string3 = seq3.elements.elementAt(1) as ASN1PrintableString;
    expect(oi3.objectIdentifierAsString, '2.5.4.11');
    expect(string3.stringValue, 'www.digicert.com');

    var set4 = sequence.elements.elementAt(3) as ASN1Set;
    expect(set4.elements.length, 1);
    expect(set4.elements.elementAt(0) is ASN1Sequence, true);

    var seq4 = set4.elements.elementAt(0) as ASN1Sequence;
    expect(seq4.elements.length, 2);
    expect(seq4.elements.elementAt(0) is ASN1ObjectIdentifier, true);
    expect(seq4.elements.elementAt(1) is ASN1PrintableString, true);
    var oi4 = seq4.elements.elementAt(0) as ASN1ObjectIdentifier;
    var string4 = seq4.elements.elementAt(1) as ASN1PrintableString;
    expect(oi4.objectIdentifierAsString, '2.5.4.3');
    expect(string4.stringValue, 'Thawte RSA CA 2018');
  });
}
