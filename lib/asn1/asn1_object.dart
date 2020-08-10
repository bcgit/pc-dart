import 'dart:typed_data';

import 'package:pointycastle/asn1/asn1_utils.dart';

///
/// Base model for all ASN1Objects
///
class ASN1Object {
  ///
  /// The BER tag representing this object.
  ///
  /// For a list of all supported BER tags take a look in the **Asn1Tags** class.
  ///
  int tag;

  ///
  /// The encoded bytes.
  ///
  Uint8List encodedBytes;

  ///
  /// The value bytes.
  ///
  Uint8List valueBytes;

  ///
  /// The index where the value bytes start. This is the position after the tag + length bytes.
  ///
  /// The default value for this field is 2. If the length byte is larger than **127**, the value of this field will increase depending on the length bytes.
  ///
  int valueStartPosition = 2;

  ///
  /// Length of the encoded value bytes.
  ///
  int valueByteLength;

  ASN1Object({this.tag});

  ///
  /// Creates a new ASN1Object from the given [encodedBytes].
  ///
  /// The first byte will be used as the [tag].The field [valueStartPosition] and [valueByteLength] will be calculated on the given [encodedBytes].
  ///
  ASN1Object.fromBytes(this.encodedBytes) {
    tag = encodedBytes[0];
    valueByteLength = ASN1Utils.decodeLength(encodedBytes);
    valueStartPosition = ASN1Utils.calculateValueStartPosition(encodedBytes);
    valueBytes = Uint8List.view(encodedBytes.buffer,
        valueStartPosition + encodedBytes.offsetInBytes, valueByteLength);
  }

  ///
  /// Encode the object to their byte representation.
  ///
  /// **Important note**: Subclasses need to override this method and may call this method. If this method is called by a subclass, the subclass has to set the [valueBytes] before calling super.encode().
  ///
  Uint8List encode() {
    if (encodedBytes == null) {
      // Encode the length
      Uint8List lengthAsBytes;
      valueByteLength ??= valueBytes.length;
      lengthAsBytes = ASN1Utils.encodeLength(valueByteLength);
      // Create the Uint8List with the calculated length
      encodedBytes = Uint8List(1 + lengthAsBytes.length + valueByteLength);
      // Set the tag
      encodedBytes[0] = tag;
      // Set the length bytes
      encodedBytes.setRange(1, 1 + lengthAsBytes.length, lengthAsBytes, 0);
      // Set the value bytes
      encodedBytes.setRange(
          1 + lengthAsBytes.length, encodedBytes.length, valueBytes, 0);
    }
    return encodedBytes;
  }
}
