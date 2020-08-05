import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/asn1/asn1_object.dart';
import 'package:pointycastle/asn1/asn1_tags.dart';

///
/// An ASN1 Printable String object
///
class ASN1PrintableString extends ASN1Object {
  ///
  /// The ascii decoded string value
  ///
  String stringValue;

  ///
  /// Create an [ASN1PrintableString] entity with the given [stringValue].
  ///
  ASN1PrintableString(this.stringValue, {int tag = ASN1Tags.PRINTABLE_STRING})
      : super(tag: tag);

  ///
  /// Creates an [ASN1PrintableString] entity from the given [encodedBytes].
  ///
  ASN1PrintableString.fromBytes(Uint8List encodedBytes)
      : super.fromBytes(encodedBytes) {
    stringValue = ascii.decode(valueBytes);
  }

  @override
  Uint8List encode() {
    var octets = ascii.encode(stringValue);
    valueByteLength = octets.length;
    valueBytes = Uint8List.fromList(octets);
    return super.encode();
  }
}
