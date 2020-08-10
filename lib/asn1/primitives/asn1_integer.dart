import 'dart:typed_data';

import 'package:pointycastle/asn1/asn1_object.dart';
import 'package:pointycastle/asn1/asn1_tags.dart';
import 'package:pointycastle/src/utils.dart';

class ASN1Integer extends ASN1Object {
  ///
  /// The integer value
  ///
  BigInt integer;

  ///
  /// Create an [ASN1Integer] entity with the given BigInt [integer].
  ///
  ASN1Integer(this.integer, {int tag = ASN1Tags.INTEGER}) : super(tag: tag);

  ///
  /// Create an [ASN1Integer] entity with the given int [i].
  ///
  ASN1Integer.fromtInt(int i, {int tag = ASN1Tags.INTEGER}) : super(tag: tag) {
    integer = BigInt.from(i);
  }

  ///
  /// Creates an [ASN1Integer] entity from the given [encodedBytes].
  ///
  ASN1Integer.fromBytes(Uint8List encodedBytes)
      : super.fromBytes(encodedBytes) {
    integer = decodeBigInt(valueBytes);
  }

  @override
  Uint8List encode() {
    valueBytes = encodeBigInt(integer);
    valueByteLength = valueBytes.length;
    return super.encode();
  }
}
