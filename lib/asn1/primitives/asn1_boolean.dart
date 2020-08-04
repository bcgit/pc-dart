import 'dart:typed_data';

import 'package:pointycastle/asn1/asn1_object.dart';
import 'package:pointycastle/asn1/asn1_tags.dart';

///
/// An ASN1 Boolean object
///
class ASN1Boolean extends ASN1Object {
  bool boolValue;

  ///
  /// The byte to use for the TRUE value
  ///
  static const int BOOLEAN_TRUE_VALUE = 0xff;

  ///
  /// The byte to use for the FALSE value
  ///
  static const int BOOLEAN_FALSE_VALUE = 0x00;

  ///
  /// Creates an [ASN1Boolean] entity with the given [boolValue].
  ///
  ASN1Boolean(this.boolValue, {int tag = ASN1Tags.BOOLEAN}) : super(tag: tag);

  ///
  /// Creates an [ASN1Boolean] entity from the given [encodedBytes].
  ///
  ASN1Boolean.fromBytes(Uint8List encodedBytes)
      : super.fromBytes(encodedBytes) {
    boolValue = (valueBytes[0] == BOOLEAN_TRUE_VALUE);
  }

  ///
  /// Encode the [ASN1Boolean] to the byte representation.
  ///
  @override
  Uint8List encode() {
    valueByteLength = 1;
    valueBytes = (boolValue == true)
        ? Uint8List.fromList([BOOLEAN_TRUE_VALUE])
        : Uint8List.fromList([BOOLEAN_FALSE_VALUE]);
    return super.encode();
  }
}
