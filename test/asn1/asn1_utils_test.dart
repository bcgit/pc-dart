import 'dart:typed_data';

import 'package:pointycastle/asn1/asn1_utils.dart';
import 'package:test/test.dart';

void main() {
  test('Test decodeLength', () {
    // Test with second byte larger than 127
    expect(ASN1Utils.decodeLength(Uint8List.fromList([0x30, 0x82, 0x01, 0x26])),
        294);
    // Test with second byte larger than 127 but missing byte at the end
    try {
      ASN1Utils.decodeLength(Uint8List.fromList([0x0, 0x82, 0x01]));
      fail('Expected RangeError due to missing byte');
    } catch (e) {
      expect(e, e as RangeError);
    }
    // Test with second byte less than 127
    expect(ASN1Utils.decodeLength(Uint8List.fromList([0x02, 0x01, 0x00])), 1);
    expect(
        ASN1Utils.decodeLength(Uint8List.fromList([
          0x0C,
          0x0B,
          0x45,
          0x6E,
          0x74,
          0x77,
          0x69,
          0x63,
          0x6B,
          0x6C,
          0x75,
          0x6E,
          0x67
        ])),
        11);
  });

  test('Test encodeLength', () {
    // Test with length larger than 127
    expect(ASN1Utils.encodeLength(294), Uint8List.fromList([0x82, 0x01, 0x26]));
    // Test with length less than 127
    expect(ASN1Utils.encodeLength(1), Uint8List.fromList([0x01]));
    expect(ASN1Utils.encodeLength(11), Uint8List.fromList([0x0B]));
  });

  test('Test calculateValueStartPosition', () {
    // Test with length larger than 127
    expect(
        ASN1Utils.calculateValueStartPosition(
            Uint8List.fromList([0x30, 0x82, 0x01, 0x26])),
        4);
    // Test with length less than 127
    expect(
        ASN1Utils.calculateValueStartPosition(
            Uint8List.fromList([0x02, 0x01, 0x00])),
        2);
    // Test with only one byte
    try {
      ASN1Utils.calculateValueStartPosition(Uint8List.fromList([0x0]));
      fail('Expected RangeError due to missing byte');
    } catch (e) {
      expect(e, e as RangeError);
    }
  });
}
