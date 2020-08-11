import 'dart:typed_data';

import 'package:pointycastle/asn1/asn1_object.dart';
import 'package:pointycastle/asn1/asn1_parser.dart';
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
    elements = [];
    var parser = ASN1Parser(valueBytes);
    while (parser.hasNext()) {
      elements.add(parser.nextObject());
    }
  }

  @override
  Uint8List encode() {
    valueByteLength = _childLength();
    var i = valueStartPosition;
    elements.forEach((obj) {
      var b = obj.encode();
      valueBytes.setRange(i, i + b.length, b);
      i += b.length;
    });
    return super.encode();
  }

  ///
  /// Calculate encoded length of all children
  ///
  int _childLength() {
    var l = 0;
    elements.forEach((ASN1Object obj) {
      l += obj.encode().length;
    });
    return l;
  }
}
