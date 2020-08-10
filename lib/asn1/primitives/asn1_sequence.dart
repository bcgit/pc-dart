import 'dart:typed_data';

import 'package:pointycastle/asn1/asn1_object.dart';
import 'package:pointycastle/asn1/asn1_tags.dart';

class ASN1Sequence extends ASN1Object {
  ///
  /// The decoded string value
  ///
  List<ASN1Object> elements;

  ///
  /// Create an [ASN1Sequence] entity with the given [elements].
  ///
  ASN1Sequence({this.elements, int tag = ASN1Tags.SEQUENCE}) : super(tag: tag);

  ///
  /// Creates an [ASN1Sequence] entity from the given [encodedBytes].
  ///
  ASN1Sequence.fromBytes(Uint8List encodedBytes)
      : super.fromBytes(encodedBytes) {
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
