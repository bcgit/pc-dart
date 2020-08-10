import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/asn1/asn1_object.dart';
import 'package:pointycastle/asn1/asn1_tags.dart';

///
/// An ASN1 UTF8 String object
///
class ASN1UTF8String extends ASN1Object {
  ///
  /// The decoded string value
  ///
  String utf8StringValue;

  ///
  /// Creates an empty [ASN1UTF8String] entity with only the [tag] set.
  ///
  ASN1UTF8String(this.utf8StringValue, {int tag = ASN1Tags.UTF8_STRING})
      : super(tag: tag);

  ///
  /// Creates an [ASN1UTF8String] entity from the given [encodedBytes].
  ///
  ASN1UTF8String.fromBytes(Uint8List encodedBytes)
      : super.fromBytes(encodedBytes) {
    utf8StringValue = utf8.decode(valueBytes);
  }

  ///
  /// Encode the [ASN1UTF8String] to the byte representation.
  ///
  @override
  Uint8List encode() {
    var octets = utf8.encode(utf8StringValue);
    valueByteLength = octets.length;
    valueBytes = Uint8List.fromList(octets);
    return super.encode();
  }
}
