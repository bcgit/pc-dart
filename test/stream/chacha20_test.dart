// See file LICENSE for more information.

library pointycastle.test.stream.chacha20_test;

import "dart:typed_data";

import "package:pointycastle/pointycastle.dart";
import 'package:pointycastle/stream/chacha20.dart';

import "../test/src/helpers.dart";

void main() {
  String set1v0_0 = "FBB87FBB8395E05DAA3B1D683C422046"
      + "F913985C2AD9B23CFC06C1D8D04FF213"
      + "D44A7A7CDB84929F915420A8A3DC58BF"
      + "0F7ECB4B1F167BB1A5E6153FDAF4493D";

  String set1v0_192 = "D9485D55B8B82D792ED1EEA8E93E9BC1"
      + "E2834AD0D9B11F3477F6E106A2F6A5F2"
      + "EA8244D5B925B8050EAB038F58D4DF57"
      + "7FAFD1B89359DAE508B2B10CBD6B488E";

  String set1v0_256 = "08661A35D6F02D3D9ACA8087F421F7C8"
      + "A42579047D6955D937925BA21396DDD4"
      + "74B1FC4ACCDCAA33025B4BCE817A4FBF"
      + "3E5D07D151D7E6FE04934ED466BA4779";

  String set1v0_448 = "A7E16DD38BA48CCB130E5BE9740CE359"
      + "D631E91600F85C8A5D0785A612D1D987"
      + "90780ACDDC26B69AB106CCF6D866411D"
      + "10637483DBF08CC5591FD8B3C87A3AE0";

  String set1v9_0 = "A276339F99316A913885A0A4BE870F06"
      + "91E72B00F1B3F2239F714FE81E88E00C"
      + "BBE52B4EBBE1EA15894E29658C4CB145"
      + "E6F89EE4ABB045A78514482CE75AFB7C";

  String set1v9_192 = "0DFB9BD4F87F68DE54FBC1C6428FDEB0"
      + "63E997BE8490C9B7A4694025D6EBA2B1"
      + "5FE429DB82A7CAE6AAB22918E8D00449"
      + "6FB6291467B5AE81D4E85E81D8795EBB";

  String set1v9_256 = "546F5BB315E7F71A46E56D4580F90889"
      + "639A2BA528F757CF3B048738BA141AF3"
      + "B31607CB21561BAD94721048930364F4"
      + "B1227CFEB7CDECBA881FB44903550E68";

  String set1v9_448 = "6F813586E76691305A0CF048C0D8586D"
      + "C89460207D8B230CD172398AA33D19E9"
      + "2D24883C3A9B0BB7CD8C6B2668DB142E"
      + "37A97948A7A01498A21110297984CD20";

  // ChaCha12
  String chacha12_set1v0_0 = "36CF0D56E9F7FBF287BC5460D95FBA94"
      + "AA6CBF17D74E7C784DDCF7E0E882DDAE"
      + "3B5A58243EF32B79A04575A8E2C2B73D"
      + "C64A52AA15B9F88305A8F0CA0B5A1A25";

  String chacha12_set1v0_192 = "83496792AB68FEC75ADB16D3044420A4"
      + "A00A6E9ADC41C3A63DBBF317A8258C85"
      + "A9BC08B4F76B413A4837324AEDF8BC2A"
      + "67D53C9AB9E1C5BC5F379D48DF9AF730";

  String chacha12_set1v0_256 = "BAA28ED593690FD760ADA07C95E3B888"
      + "4B4B64E488CA7A2D9BDC262243AB9251"
      + "394C5037E255F8BCCDCD31306C508FFB"
      + "C9E0161380F7911FCB137D46D9269250";

  String chacha12_set1v0_448 = "B7ECFB6AE0B51915762FE1FD03A14D0C"
      + "9E54DA5DC76EB16EBA5313BC535DE63D"
      + "C72D7F9F1874E301E99C8531819F4E37"
      + "75793F6A5D19C717FA5C78A39EB804A6";

  // ChaCha8
  String chacha8_set1v0_0 = "BEB1E81E0F747E43EE51922B3E87FB38"
      + "D0163907B4ED49336032AB78B67C2457"
      + "9FE28F751BD3703E51D876C017FAA435"
      + "89E63593E03355A7D57B2366F30047C5";

  String chacha8_set1v0_192 = "33B8B7CA8F8E89F0095ACE75A379C651"
      + "FD6BDD55703C90672E44C6BAB6AACDD8"
      + "7C976A87FD264B906E749429284134C2"
      + "38E3B88CF74A68245B860D119A8BDF43";

  String chacha8_set1v0_256 = "F7CA95BF08688BD3BE8A27724210F9DC"
      + "16F32AF974FBFB09E9F757C577A245AB"
      + "F35F824B70A4C02CB4A8D7191FA8A5AD"
      + "6A84568743844703D353B7F00A8601F4";

  String chacha8_set1v0_448 = "7B4117E8BFFD595CD8482270B08920FB"
      + "C9B97794E1809E07BB271BF07C861003"
      + "4C38DBA6ECA04E5474F399A284CBF6E2"
      + "7F70142E604D0977797DE5B58B6B25E0";


  chachaTest1(20, ParametersWithIV(KeyParameter(createUint8ListFromHexString("80000000000000000000000000000000")), createUint8ListFromHexString("0000000000000000")), set1v0_0, set1v0_192,  set1v0_256,  set1v0_448);
  chachaTest1(20, ParametersWithIV(KeyParameter(createUint8ListFromHexString("00400000000000000000000000000000")), createUint8ListFromHexString("0000000000000000")), set1v9_0, set1v9_192,  set1v9_256,  set1v9_448);
  chachaTest1(12, ParametersWithIV(KeyParameter(createUint8ListFromHexString("80000000000000000000000000000000")), createUint8ListFromHexString("0000000000000000")), chacha12_set1v0_0, chacha12_set1v0_192,  chacha12_set1v0_256,  chacha12_set1v0_448);
  chachaTest1(8, ParametersWithIV(KeyParameter(createUint8ListFromHexString("80000000000000000000000000000000")), createUint8ListFromHexString("0000000000000000")), chacha8_set1v0_0, chacha8_set1v0_192,  chacha8_set1v0_256,  chacha8_set1v0_448);
}

void chachaTest1(int rounds, CipherParameters params, String v0, String v192, String v256, String v448) {
  StreamCipher chaCha = ChaCha20Engine.fromRounds(rounds);
  Uint8List buf = Uint8List(64);

  chaCha.init(true, params);

  Uint8List zeroes = createUint8ListFromHexString(
      "00000000000000000000000000000000"
          + "00000000000000000000000000000000"
          + "00000000000000000000000000000000"
          + "00000000000000000000000000000000");

  for (int i = 0; i != 7; i++) {
    chaCha.processBytes(zeroes, 0, 64, buf, 0);
    switch (i) {
      case 0:
        if (!areEqual(buf, createUint8ListFromHexString(v0))) {
          throw ArgumentError();
        }
        break;
      case 3:
        if (!areEqual(buf, createUint8ListFromHexString(v192))) {
          throw ArgumentError();
        }
        break;
      case 4:
        if (!areEqual(buf, createUint8ListFromHexString(v256)))
        {
          throw ArgumentError();
        }
        break;
      default:
      // ignore
    }
  }

  for (int i = 0; i != 64; i++) {
    buf[i] = chaCha.returnByte(zeroes[i]);
  }

  if (!areEqual(buf, createUint8ListFromHexString(v448))) {
    throw ArgumentError();
  }
}

bool areEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (int i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}