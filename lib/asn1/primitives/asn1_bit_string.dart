import 'dart:typed_data';

import 'package:pointycastle/asn1/asn1_encoding_rule.dart';
import 'package:pointycastle/asn1/asn1_object.dart';
import 'package:pointycastle/asn1/asn1_parser.dart';
import 'package:pointycastle/asn1/asn1_tags.dart';
import 'package:pointycastle/asn1/asn1_utils.dart';
import 'package:pointycastle/asn1/unsupported_asn1_encoding_rule_exception.dart';

///
/// An ASN1 Bit String object
///
class ASN1BitString extends ASN1Object {
  ///
  /// The decoded string value
  ///
  List<int> stringValues;

  ///
  /// A list of elements. Only set if this ASN1IA5String is constructed, otherwhise null.
  ///
  ///
  List<ASN1Object> elements;

  ///
  /// Create an [ASN1BitString] entity with the given [stringValues].
  ///
  ASN1BitString(
      {this.stringValues, this.elements, int tag = ASN1Tags.BIT_STRING})
      : super(tag: tag);

  ///
  /// Creates an [ASN1BitString] entity from the given [encodedBytes].
  ///
  ASN1BitString.fromBytes(Uint8List bytes) : super.fromBytes(bytes) {
    if (ASN1Utils.isConstructed(encodedBytes.elementAt(0))) {
      elements = [];
      var parser = ASN1Parser(valueBytes);
      stringValues = [];
      while (parser.hasNext()) {
        var bitString = parser.nextObject() as ASN1BitString;
        stringValues.addAll(bitString.stringValues);
        elements.add(bitString);
      }
    } else {
      stringValues = valueBytes.sublist(1);
    }
  }

  ///
  /// Encodes this ASN1Object depending on the given [encodingRule]
  ///
  /// If no [ASN1EncodingRule] is given, ENCODING_DER will be used.
  ///
  /// Supported encoding rules are :
  /// * [ASN1EncodingRule.ENCODING_DER]
  /// * [ASN1EncodingRule.ENCODING_BER_LONG_LENGTH_FORM]
  /// * [ASN1EncodingRule.ENCODING_BER_CONSTRUCTED]
  /// * [ASN1EncodingRule.ENCODING_BER_CONSTRUCTED_INDEFINITE_LENGTH]
  /// * [ASN1EncodingRule.ENCODING_BER_PADDED]
  ///
  /// Throws an [UnsupportedAsn1EncodingRuleException] if the given [encodingRule] is not supported.
  ///
  @override
  Uint8List encode(
      {ASN1EncodingRule encodingRule = ASN1EncodingRule.ENCODING_DER}) {
    switch (encodingRule) {
      case ASN1EncodingRule.ENCODING_BER_PADDED:
      case ASN1EncodingRule.ENCODING_DER:
      case ASN1EncodingRule.ENCODING_BER_LONG_LENGTH_FORM:
        valueBytes = Uint8List.fromList(stringValues);
        break;
      case ASN1EncodingRule.ENCODING_BER_CONSTRUCTED_INDEFINITE_LENGTH:
      case ASN1EncodingRule.ENCODING_BER_CONSTRUCTED:
        valueByteLength = 0;
        if (elements == null) {
          elements.add(ASN1BitString(stringValues: stringValues));
        }
        valueByteLength = _childLength(
            isIndefinite: encodingRule ==
                ASN1EncodingRule.ENCODING_BER_CONSTRUCTED_INDEFINITE_LENGTH);
        valueBytes = Uint8List(valueByteLength);
        var i = 0;
        elements.forEach((obj) {
          var b = obj.encode();
          valueBytes.setRange(i, i + b.length, b);
          i += b.length;
        });
        break;
    }

    return super.encode(encodingRule: encodingRule);
  }

  ///
  /// Calculate encoded length of all children
  ///
  int _childLength({bool isIndefinite = false}) {
    var l = 0;
    elements.forEach((ASN1Object obj) {
      l += obj.encode().length;
    });
    if (isIndefinite) {
      return l + 2;
    }
    return l;
  }
}
