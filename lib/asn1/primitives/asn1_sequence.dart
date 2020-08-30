import 'dart:typed_data';

import 'package:pointycastle/asn1/asn1_encoding_rule.dart';
import 'package:pointycastle/asn1/asn1_object.dart';
import 'package:pointycastle/asn1/asn1_parser.dart';
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
    elements = [];
    var parser = ASN1Parser(valueBytes);
    while (parser.hasNext()) {
      elements.add(parser.nextObject());
    }
  }

  @override
  Uint8List encode(
      {ASN1EncodingRule encodingRule = ASN1EncodingRule.ENCODING_DER}) {
    valueBytes = Uint8List(0);
    valueByteLength = 0;
    if (elements != null) {
      valueByteLength = _childLength();
      valueBytes = Uint8List(valueByteLength);
      var i = 0;
      elements.forEach((obj) {
        var b = obj.encode();
        valueBytes.setRange(i, i + b.length, b);
        i += b.length;
      });
    }
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
