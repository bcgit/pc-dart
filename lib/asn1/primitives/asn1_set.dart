import 'dart:typed_data';

import 'package:pointycastle/asn1/asn1_object.dart';
import 'package:pointycastle/asn1/asn1_tags.dart';

class ASN1Set extends ASN1Object {
  ///
  /// The decoded string value
  ///
  List<ASN1Object> elements;

  ///
  /// Create an [ASN1Set] entity with the given [elements].
  ///
  ASN1Set({this.elements, int tag = ASN1Tags.SET}) : super(tag: tag);

  ///
  /// Creates an [ASN1Set] entity from the given [encodedBytes].
  ///
  ASN1Set.fromBytes(Uint8List encodedBytes) : super.fromBytes(encodedBytes) {
    // TODO decode value bytes to seperate asn1objects and add it to the elements list
  }

  @override
  Uint8List encode() {
    // TODO This is temporary and should be changed after adding the element feature
    valueBytes = Uint8List(0);
    valueByteLength = 0;
    return super.encode();
  }
}
