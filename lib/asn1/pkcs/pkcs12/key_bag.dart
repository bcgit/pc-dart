import 'dart:typed_data';
import 'package:pointycastle/asn1.dart';

///
///```
/// KeyBag ::= PrivateKeyInfo
///```
///
class KeyBag extends ASN1Object {
  PrivateKeyInfo privateKeyInfo;

  KeyBag(this.privateKeyInfo);

  @override
  Uint8List encode(
      {ASN1EncodingRule encodingRule = ASN1EncodingRule.ENCODING_DER}) {
    return privateKeyInfo.encode(encodingRule: encodingRule);
  }
}
