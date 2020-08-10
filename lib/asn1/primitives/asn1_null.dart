import 'dart:typed_data';

import 'package:pointycastle/asn1/asn1_object.dart';
import 'package:pointycastle/asn1/asn1_tags.dart';

///
/// An ASN1 Null object
///
class ASN1Null extends ASN1Object {
  ///
  /// Creates an empty [ASN1Null] entity with only the [tag] set.
  ///
  ASN1Null({int tag = ASN1Tags.NULL}) : super(tag: tag);

  ///
  /// Creates an [ASN1Null] entity from the given [encodedBytes].
  ///
  ASN1Null.fromBytes(Uint8List encodedBytes) : super.fromBytes(encodedBytes);

  ///
  /// Encode the [ASN1Null] to the byte representation.
  ///
  /// This basically returns **[0x05, 0x00]** and will not call the *super.encode()* method.
  ///
  @override
  Uint8List encode() => Uint8List.fromList([tag, 0x00]);
}
