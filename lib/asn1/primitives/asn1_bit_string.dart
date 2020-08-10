import 'dart:typed_data';

import 'package:pointycastle/asn1/asn1_object.dart';
import 'package:pointycastle/asn1/asn1_tags.dart';

///
/// An ASN1 Bit String object
///
class ASN1BitString extends ASN1Object {
  ///
  /// The decoded string value
  ///
  List<int> stringValues;

  ///
  /// Create an [ASN1BitString] entity with the given [stringValues].
  ///
  ASN1BitString(this.stringValues, {int tag = ASN1Tags.BIT_STRING})
      : super(tag: tag);

  ///
  /// Creates an [ASN1BitString] entity from the given [encodedBytes].
  ///
  ASN1BitString.fromBytes(Uint8List bytes) : super.fromBytes(bytes) {
    stringValues = valueBytes.sublist(1);
  }

  ///
  /// Encode the [ASN1BitString] to the byte representation.
  ///
  @override
  Uint8List encode() {
    valueBytes = Uint8List.fromList(stringValues);
    return super.encode();
  }
}
