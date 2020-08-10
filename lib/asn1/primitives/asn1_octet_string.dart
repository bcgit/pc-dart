import 'dart:typed_data';

import 'package:pointycastle/asn1/asn1_object.dart';
import 'package:pointycastle/asn1/asn1_tags.dart';

///
/// An ASN1 Octed String object
///
class ASN1OctetString extends ASN1Object {
  ///
  /// The decoded string value
  ///
  Uint8List octets;

  ///
  /// Create an [ASN1OctetString] entity with the given [octets].
  ///
  ASN1OctetString(this.octets, {int tag = ASN1Tags.OCTET_STRING})
      : super(tag: tag);

  ///
  /// Creates an [ASN1OctetString] entity from the given [encodedBytes].
  ///
  ASN1OctetString.fromBytes(Uint8List encodedBytes)
      : super.fromBytes(encodedBytes) {
    octets = valueBytes;
  }

  @override
  Uint8List encode() {
    valueByteLength = octets.length;
    valueBytes = octets;
    return super.encode();
  }
}
