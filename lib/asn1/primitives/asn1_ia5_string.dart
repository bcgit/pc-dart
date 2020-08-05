import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/asn1/asn1_object.dart';
import 'package:pointycastle/asn1/asn1_tags.dart';

///
/// An ASN1 IA5 String object
///
class ASN1IA5String extends ASN1Object {
  ///
  /// The ascii decoded string value
  ///
  String stringValue;

  ///
  /// Create an [ASN1IA5String] entity with the given [stringValue].
  ///
  ASN1IA5String(this.stringValue, {int tag = ASN1Tags.IA5_STRING})
      : super(tag: tag);

  ///
  /// Creates an [ASN1IA5String] entity from the given [encodedBytes].
  ///
  ASN1IA5String.fromBytes(Uint8List encodedBytes)
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
