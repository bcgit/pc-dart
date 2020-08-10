import 'dart:typed_data';

import 'package:pointycastle/asn1/asn1_object.dart';
import 'package:pointycastle/asn1/asn1_tags.dart';

class ASN1ObjectIdentifier extends ASN1Object {
  ///
  /// The object identifier integer values
  ///
  List<int> objectIdentifier;

  ///
  /// The String representation of the [objectIdentifier]
  ///
  String objectIdentifierAsString;

  ///
  /// Create an [ASN1ObjectIdentifier] entity with the given [objectIdentifier].
  ///
  ASN1ObjectIdentifier(this.objectIdentifier,
      {int tag = ASN1Tags.OBJECT_IDENTIFIER})
      : super(tag: tag) {
    objectIdentifierAsString = objectIdentifier.join('.');
  }

  ///
  /// Creates an [ASN1ObjectIdentifier] entity from the given [encodedBytes].
  ///
  ASN1ObjectIdentifier.fromBytes(Uint8List encodedBytes)
      : super.fromBytes(encodedBytes) {
    var value = 0;
    var first = true;
    BigInt bigValue;
    var list = <int>[];
    var sb = StringBuffer();
    valueBytes.forEach((element) {
      var b = element & 0xff;
      if (value < 0x80000000000000) {
        value = value * 128 + (b & 0x7f);
        if ((b & 0x80) == 0) {
          if (first) {
            var truncated = value ~/ 40;
            if (truncated < 2) {
              list.add(truncated);
              sb.write(truncated);
              value -= truncated * 40;
            } else {
              list.add(2);
              sb.write('2');
              value -= 80;
            }
            first = false;
          }
          list.add(value);
          sb.write('.$value');
          value = 0;
        }
      } else {
        bigValue ??= BigInt.from(value);
        bigValue = bigValue << (7);
        bigValue = bigValue | BigInt.from(b & 0x7f);
        if ((b & 0x80) == 0) {
          sb.write('.$bigValue');
          bigValue = null;
          value = 0;
        }
      }
    });
    objectIdentifierAsString = sb.toString();
    objectIdentifier = Uint8List.fromList(list);
  }

  ///
  /// Creates an [ASN1ObjectIdentifier] entity from the given [name].
  ///
  /// Example for [name]:
  /// ```
  /// var name = 'ecdsaWithSHA256'
  /// ```
  ///
  ASN1ObjectIdentifier.fromName(String name) {
    // TODO Implement named constructor fromName()
    throw UnimplementedError();
  }

  ///
  /// Creates an [ASN1ObjectIdentifier] entity from the given [componentString].
  ///
  /// Example for [componentString]:
  /// ```
  /// var componentString = '2.5.4.3'
  /// ```
  ///
  ASN1ObjectIdentifier.fromComponentString(this.objectIdentifierAsString,
      {int tag = ASN1Tags.OBJECT_IDENTIFIER})
      : super(tag: tag) {
    var list = objectIdentifierAsString.split('.').map(int.parse).toList();
    objectIdentifier = Uint8List.fromList(list);
  }

  @override
  Uint8List encode() {
    var oi = <int>[];
    oi.add(objectIdentifier[0] * 40 + objectIdentifier[1]);

    for (var ci = 2; ci < objectIdentifier.length; ci++) {
      var position = oi.length;
      var v = objectIdentifier[ci];
      assert(v > 0);

      var first = true;
      do {
        var remainder = v & 127;
        v = v >> 7;
        if (first) {
          first = false;
        } else {
          remainder |= 0x80;
        }

        oi.insert(position, remainder);
      } while (v > 0);
    }

    valueBytes = Uint8List.fromList(oi);
    valueByteLength = oi.length;

    return super.encode();
  }
}
