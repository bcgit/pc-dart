///
/// Class holding all ASN1 BER tags, supported by this package
///
class ASN1Tags {
  /// Decimal 1
  static const int BOOLEAN = 0x01;

  /// Decimal 2
  static const int INTEGER = 0x02;

  /// Decimal 3
  static const int BIT_STRING = 0x03;

  /// Decimal 4
  static const int OCTET_STRING = 0x04;

  /// Decimal 5
  static const int NULL = 0x05;

  /// Decimal 6
  static const int OBJECT_IDENTIFIER = 0x06;

  /// Decimal 8
  static const int EXTERNAL = 0x08;

  /// Decimal 10
  static const int ENUMERATED = 0x0a;

  /// Decimal 12
  static const int UTF8_STRING = 0x0c;

  /// Decimal 48
  static const int SEQUENCE = 0x30;

  /// Decimal 48
  static const int SEQUENCE_OF = 0x30;

  /// Decimal 49
  static const int SET = 0x31;

  /// Decimal 49
  static const int SET_OF = 0x31;

  /// Decimal 18
  static const int NUMERIC_STRING = 0x12;

  /// Decimal 19
  static const int PRINTABLE_STRING = 0x13;

  /// Decimal 20
  static const int T61_STRING = 0x14;

  /// Decimal 21
  static const int VIDEOTEX_STRING = 0x15;

  /// Decimal 22
  static const int IA5_STRING = 0x16;

  /// Decimal 23
  static const int UTC_TIME = 0x17;

  /// Decimal 24
  static const int GENERALIZED_TIME = 0x18;

  /// Decimal 25
  static const int GRAPHIC_STRING = 0x19;

  /// Decimal 26
  static const int VISIBLE_STRING = 0x1a;

  /// Decimal 27
  static const int GENERAL_STRING = 0x1b;

  /// Decimal 28
  static const int UNIVERSAL_STRING = 0x1c;

  /// Decimal 30
  static const int BMP_STRING = 0x1e;

  /// Decimal 32
  static const int CONSTRUCTED = 0x20;

  /// Decimal 64
  static const int APPLICATION = 0x40;

  /// Decimal 128
  static const int TAGGED = 0x80;
}
