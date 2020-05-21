// See file LICENSE for more information.

library pointycastle.src.ufixnum_test;

import 'dart:typed_data';

import "package:test/test.dart";
import "package:pointycastle/src/ufixnum.dart";

void main() {
  group("int8:", () {
    test("clip8()", () {
      expect(clip8(0x00), 0x00);
      expect(clip8(0xFF), 0xFF);
      expect(clip8(0x100), 0x00);
    });

    test("sum8()", () {
      expect(sum8(0x00, 0x01), 0x01);
      expect(sum8(0xFF, 0x01), 0x00);
    });

    test("sub8()", () {
      expect(sub8(0x00, 0x01), 0xFF);
      expect(sub8(0xFF, 0x01), 0xFE);
    });

    test("shiftl8()", () {
      expect(shiftl8(0xAB, 0), 0xAB);
      expect(shiftl8(0xAB, 4), 0xB0);
      expect(shiftl8(0xAB, 8), 0xAB);
    });

    test("shiftr8()", () {
      expect(shiftr8(0xAB, 0), 0xAB);
      expect(shiftr8(0xAB, 4), 0x0A);
      expect(shiftr8(0xAB, 8), 0xAB);
    });

    test("neg8()", () {
      expect(neg8(0x00), 0x00);
      expect(neg8(0xFF), 0x01);
      expect(neg8(0x01), 0xFF);
    });

    test("not8()", () {
      expect(not8(0x00), 0xFF);
      expect(not8(0xFF), 0x00);
      expect(not8(0x01), 0xFE);
    });

    test("rotl8()", () {
      expect(rotl8(0xAB, 0), 0xAB);
      expect(rotl8(0x7F, 1), 0xFE);
      expect(rotl8(0xAB, 4), 0xBA);
      expect(rotl8(0xAB, 8), 0xAB);
    });

    test("rotr8()", () {
      expect(rotr8(0xAB, 0), 0xAB);
      expect(rotr8(0xFE, 1), 0x7F);
      expect(rotr8(0xAB, 4), 0xBA);
      expect(rotr8(0xAB, 8), 0xAB);
    });
  });

  group("int16:", () {
    test("clip16()", () {
      expect(clip16(0x0000), 0x0000);
      expect(clip16(0xFFFF), 0xFFFF);
      expect(clip16(0x10000), 0x0000);
    });

    test("pack16(BIG_ENDIAN)", () {
      var out = new Uint8List(2);
      pack16(0x1020, out, 0, Endian.big);
      expect(out[0], 0x10);
      expect(out[1], 0x20);
    });

    test("pack16(LITTLE_ENDIAN)", () {
      var out = new Uint8List(2);
      pack16(0x1020, out, 0, Endian.little);
      expect(out[1], 0x10);
      expect(out[0], 0x20);
    });

    test("unpack16(BIG_ENDIAN)", () {
      var inp = new Uint8List.fromList([0x10, 0x20]);
      expect(unpack16(inp, 0, Endian.big), 0x1020);
    });

    test("unpack16(LITTLE_ENDIAN)", () {
      var inp = new Uint8List.fromList([0x20, 0x10]);
      expect(unpack16(inp, 0, Endian.little), 0x1020);
    });

    test("pack16(Uint8List.view)", () {
      var out = new Uint8List(6);
      out = new Uint8List.view(out.buffer, 2, 2);
      pack16(0x1020, out, 0, Endian.big);
      expect(out[0], 0x10);
      expect(out[1], 0x20);
    });

    test("unpack16(Uint8List.view)", () {
      var inp = new Uint8List.fromList([0, 0, 0x20, 0x10, 0, 0]);
      inp = new Uint8List.view(inp.buffer, 2, 2);
      expect(unpack16(inp, 0, Endian.little), 0x1020);
    });
  });

  group("int32:", () {
    test("clip32()", () {
      expect(clip32(0x00000000), 0x00000000);
      expect(clip32(0xFFFFFFFF), 0xFFFFFFFF);
      expect(clip32(0x100000000), 0x00000000);
    });

    test("sum32()", () {
      expect(sum32(0x00000000, 0x00000001), 0x00000001);
      expect(sum32(0xFFFFFFFF, 0x00000001), 0x00000000);
    });

    test("sub32()", () {
      expect(sub32(0x00000000, 0x00000001), 0xFFFFFFFF);
      expect(sub32(0xFFFFFFFF, 0x00000001), 0xFFFFFFFE);
    });

    test("shiftl32()", () {
      expect(shiftl32(0x10203040, 0), 0x10203040);
      expect(shiftl32(0x10203040, 16), 0x30400000);
      expect(shiftl32(0x10203040, 32), 0x10203040);
    });

    test("shiftr32()", () {
      expect(shiftr32(0x10203040, 0), 0x10203040);
      expect(shiftr32(0x10203040, 16), 0x00001020);
      expect(shiftr32(0x10203040, 32), 0x10203040);
      expect(shiftr32(0x80000000, 8), 0x00800000);
    });

    test("neg32()", () {
      expect(neg32(0x00000000), 0x00000000);
      expect(neg32(0xFFFFFFFF), 0x00000001);
      expect(neg32(0x00000001), 0xFFFFFFFF);
    });

    test("not32()", () {
      expect(not32(0x00000000), 0xFFFFFFFF);
      expect(not32(0xFFFFFFFF), 0x00000000);
      expect(not32(0x00000001), 0xFFFFFFFE);
    });

    test("rotl32()", () {
      expect(rotl32(0x10203040, 0), 0x10203040);
      expect(rotl32(0x10203040, 8), 0x20304010);
      expect(rotl32(0x10203040, 16), 0x30401020);
      expect(rotl32(0x10203040, 32), 0x10203040);
    });

    test("rotr32()", () {
      expect(rotr32(0x10203040, 0), 0x10203040);
      expect(rotr32(0x10203040, 8), 0x40102030);
      expect(rotr32(0x10203040, 16), 0x30401020);
      expect(rotr32(0x10203040, 32), 0x10203040);
    });

    test("pack32(BIG_ENDIAN)", () {
      var out = new Uint8List(4);
      pack32(0x10203040, out, 0, Endian.big);
      expect(out[0], 0x10);
      expect(out[1], 0x20);
      expect(out[2], 0x30);
      expect(out[3], 0x40);
    });

    test("pack32(LITTLE_ENDIAN)", () {
      var out = new Uint8List(4);
      pack32(0x10203040, out, 0, Endian.little);
      expect(out[3], 0x10);
      expect(out[2], 0x20);
      expect(out[1], 0x30);
      expect(out[0], 0x40);
    });

    test("unpack32(BIG_ENDIAN)", () {
      var inp = new Uint8List.fromList([0x10, 0x20, 0x30, 0x40]);
      expect(unpack32(inp, 0, Endian.big), 0x10203040);
    });

    test("unpack32(LITTLE_ENDIAN)", () {
      var inp = new Uint8List.fromList([0x40, 0x30, 0x20, 0x10]);
      expect(unpack32(inp, 0, Endian.little), 0x10203040);
    });

    test("pack32(Uint8List.view)", () {
      var out = new Uint8List(8);
      out = new Uint8List.view(out.buffer, 2, 4);
      pack32(0x10203040, out, 0, Endian.big);
      expect(out[0], 0x10);
      expect(out[1], 0x20);
      expect(out[2], 0x30);
      expect(out[3], 0x40);
    });

    test("unpack32(Uint8List.view)", () {
      var inp = new Uint8List.fromList([0, 0, 0x40, 0x30, 0x20, 0x10, 0, 0]);
      inp = new Uint8List.view(inp.buffer, 2, 4);
      expect(unpack32(inp, 0, Endian.little), 0x10203040);
    });
  });

  group("Register64:", () {
    test("Register64(hi,lo)", () {
      expect(new Register64(0x00000000, 0x00000000),
          new Register64(0x00000000, 0x00000000));
      expect(new Register64(0x10203040, 0xFFFFFFFF),
          new Register64(0x10203040, 0xFFFFFFFF));
    });

    test("Register64(lo)", () {
      expect(
          new Register64(0x00000000), new Register64(0x00000000, 0x00000000));
      expect(
          new Register64(0x10203040), new Register64(0x00000000, 0x10203040));
    });

    test("Register64(y)", () {
      expect(new Register64(new Register64(0x00000000, 0x00000000)),
          new Register64(0x00000000, 0x00000000));
      expect(new Register64(new Register64(0x10203040, 0xFFFFFFFF)),
          new Register64(0x10203040, 0xFFFFFFFF));
    });

    test("==", () {
      expect(
          new Register64(0x00000000, 0x00000000) ==
              new Register64(0x00000000, 0x00000000),
          true);
      expect(
          new Register64(0x00000000, 0x00000001) ==
              new Register64(0x00000000, 0x00000000),
          false);
      expect(
          new Register64(0x00000001, 0x00000000) ==
              new Register64(0x00000000, 0x00000000),
          false);
      expect(
          new Register64(0x00000001, 0x00000001) ==
              new Register64(0x00000000, 0x00000000),
          false);
    });

    test("<", () {
      expect(
          new Register64(0x00000000, 0x00000000) <
              new Register64(0x00000000, 0x00000000),
          false);

      expect(
          new Register64(0x00000000, 0x00000001) <
              new Register64(0x00000000, 0x10000000),
          true);
      expect(
          new Register64(0x00000000, 0x20000000) <
              new Register64(0x00000000, 0x10000000),
          false);
      expect(
          new Register64(0x00000001, 0x00000000) <
              new Register64(0x00000000, 0x10000000),
          false);

      expect(
          new Register64(0x00000000, 0x00000001) <
              new Register64(0x10000000, 0x00000000),
          true);
      expect(
          new Register64(0x00000001, 0x00000001) <
              new Register64(0x10000000, 0x00000000),
          true);
      expect(
          new Register64(0x10000000, 0x00000000) <
              new Register64(0x10000000, 0x00000000),
          false);
      expect(
          new Register64(0x20000000, 0x00000001) <
              new Register64(0x10000000, 0x00000000),
          false);
    });

    test("<=", () {
      expect(
          new Register64(0x00000000, 0x00000000) <=
              new Register64(0x00000000, 0x00000000),
          true);

      expect(
          new Register64(0x00000000, 0x00000001) <=
              new Register64(0x00000000, 0x10000000),
          true);
      expect(
          new Register64(0x00000000, 0x20000000) <=
              new Register64(0x00000000, 0x10000000),
          false);
      expect(
          new Register64(0x00000001, 0x00000000) <=
              new Register64(0x00000000, 0x10000000),
          false);

      expect(
          new Register64(0x00000000, 0x00000001) <=
              new Register64(0x10000000, 0x00000000),
          true);
      expect(
          new Register64(0x00000001, 0x00000001) <=
              new Register64(0x10000000, 0x00000000),
          true);
      expect(
          new Register64(0x10000000, 0x00000000) <=
              new Register64(0x10000000, 0x00000000),
          true);
      expect(
          new Register64(0x20000000, 0x00000001) <=
              new Register64(0x10000000, 0x00000000),
          false);
    });

    test(">", () {
      expect(
          new Register64(0x00000000, 0x00000000) >
              new Register64(0x00000000, 0x00000000),
          false);

      expect(
          new Register64(0x00000000, 0x10000000) >
              new Register64(0x00000000, 0x00000001),
          true);
      expect(
          new Register64(0x00000000, 0x10000000) >
              new Register64(0x00000000, 0x20000000),
          false);
      expect(
          new Register64(0x10000000, 0x00000000) >
              new Register64(0x00000001, 0x00000000),
          true);

      expect(
          new Register64(0x10000000, 0x00000001) >
              new Register64(0x00000000, 0x00000000),
          true);
      expect(
          new Register64(0x10000000, 0x00000000) >
              new Register64(0x00000001, 0x00000001),
          true);
      expect(
          new Register64(0x10000000, 0x00000000) >
              new Register64(0x10000000, 0x00000000),
          false);
      expect(
          new Register64(0x10000000, 0x00000000) >
              new Register64(0x20000000, 0x00000001),
          false);
    });

    test(">=", () {
      expect(
          new Register64(0x00000000, 0x00000000) >=
              new Register64(0x00000000, 0x00000000),
          true);

      expect(
          new Register64(0x00000000, 0x10000000) >=
              new Register64(0x00000000, 0x00000001),
          true);
      expect(
          new Register64(0x00000000, 0x10000000) >=
              new Register64(0x00000000, 0x20000000),
          false);
      expect(
          new Register64(0x10000000, 0x00000000) >=
              new Register64(0x00000001, 0x00000000),
          true);

      expect(
          new Register64(0x10000000, 0x00000001) >=
              new Register64(0x00000000, 0x00000000),
          true);
      expect(
          new Register64(0x10000000, 0x00000000) >=
              new Register64(0x00000001, 0x00000001),
          true);
      expect(
          new Register64(0x10000000, 0x00000000) >=
              new Register64(0x10000000, 0x00000000),
          true);
      expect(
          new Register64(0x10000000, 0x00000000) >=
              new Register64(0x20000000, 0x00000001),
          false);
    });

    test("set(hi,lo)", () {
      expect(new Register64()..set(0x00000000, 0x00000000),
          new Register64(0x00000000, 0x00000000));
      expect(new Register64()..set(0x10203040, 0xFFFFFFFF),
          new Register64(0x10203040, 0xFFFFFFFF));
    });

    test("set(lo)", () {
      expect(new Register64()..set(0x00000000),
          new Register64(0x00000000, 0x00000000));
      expect(new Register64()..set(0x10203040),
          new Register64(0x00000000, 0x10203040));
    });

    test("set(y)", () {
      expect(new Register64()..set(new Register64(0x00000000, 0x00000000)),
          new Register64(0x00000000, 0x00000000));
      expect(new Register64()..set(new Register64(0x10203040, 0xFFFFFFFF)),
          new Register64(0x10203040, 0xFFFFFFFF));
    });

    test("sum(int)", () {
      expect(new Register64(0x00000000, 0x00000000)..sum(0x00000001),
          new Register64(0x00000000, 0x00000001));
      expect(new Register64(0x00000000, 0x80000000)..sum(0x80000001),
          new Register64(0x00000001, 0x00000001));
      expect(new Register64(0xFFFFFFFF, 0xFFFFFFFF)..sum(0x00000001),
          new Register64(0x00000000, 0x00000000));
    });

    test("sum(y)", () {
      expect(
          new Register64(0x00000000, 0x00000000)
            ..sum(new Register64(0x00000000, 0x00000001)),
          new Register64(0x00000000, 0x00000001));
      expect(
          new Register64(0x00000000, 0x80000000)
            ..sum(new Register64(0x00000000, 0x80000001)),
          new Register64(0x00000001, 0x00000001));
      expect(
          new Register64(0xFFFFFFFF, 0xFFFFFFFF)
            ..sum(new Register64(0x00000000, 0x00000001)),
          new Register64(0x00000000, 0x00000000));
    });

    test("sub(int)", () {
      expect(new Register64(0x00000000, 0x00000000)..sub(0x00000001),
          new Register64(0xFFFFFFFF, 0xFFFFFFFF));
      expect(new Register64(0x00000001, 0x00000001)..sub(0x80000001),
          new Register64(0x00000000, 0x80000000));
      expect(new Register64(0xFFFFFFFF, 0xFFFFFFFF)..sub(0x00000001),
          new Register64(0xFFFFFFFF, 0xFFFFFFFE));
    });

    test("sub(y)", () {
      expect(
          new Register64(0x00000000, 0x00000000)
            ..sub(new Register64(0x00000000, 0x00000001)),
          new Register64(0xFFFFFFFF, 0xFFFFFFFF));
      expect(
          new Register64(0x00000001, 0x00000001)
            ..sub(new Register64(0x00000000, 0x80000001)),
          new Register64(0x00000000, 0x80000000));
      expect(
          new Register64(0xFFFFFFFF, 0xFFFFFFFF)
            ..sub(new Register64(0x00000000, 0x00000001)),
          new Register64(0xFFFFFFFF, 0xFFFFFFFE));
    });

    test("mul(int)", () {
      expect(new Register64(0x00000000, 0x00000000)..mul(0x00000000),
          new Register64(0x00000000, 0x00000000));
      expect(new Register64(0x00000000, 0x00000000)..mul(0x00000001),
          new Register64(0x00000000, 0x00000000));
      expect(new Register64(0x00000000, 0x00000001)..mul(0x00000001),
          new Register64(0x00000000, 0x00000001));
      expect(new Register64(0x00000001, 0x00000000)..mul(0x00000001),
          new Register64(0x00000001, 0x00000000));
      expect(new Register64(0x00000000, 0x00000001)..mul(0xFFFFFFFF),
          new Register64(0x00000000, 0xFFFFFFFF));
      expect(new Register64(0x00000000, 0x80000000)..mul(0x00000004),
          new Register64(0x00000002, 0x00000000));
      expect(new Register64(0x00000000, 0x80000001)..mul(0x00000004),
          new Register64(0x00000002, 0x00000004));
      expect(new Register64(0x80000001, 0x80000001)..mul(0x00000004),
          new Register64(0x00000006, 0x00000004));
    });

    test("mul(y)", () {
      expect(
          new Register64(0x00000000, 0x00000000)
            ..mul(new Register64(0x00000000, 0x00000000)),
          new Register64(0x00000000, 0x00000000));
      expect(
          new Register64(0x00000000, 0x00000000)
            ..mul(new Register64(0x00000000, 0x00000001)),
          new Register64(0x00000000, 0x00000000));
      expect(
          new Register64(0x00000000, 0x00000001)
            ..mul(new Register64(0x00000000, 0x00000001)),
          new Register64(0x00000000, 0x00000001));
      expect(
          new Register64(0x00000001, 0x00000000)
            ..mul(new Register64(0x00000000, 0x00000001)),
          new Register64(0x00000001, 0x00000000));
      expect(
          new Register64(0x00000000, 0x00000001)
            ..mul(new Register64(0x00000000, 0xFFFFFFFF)),
          new Register64(0x00000000, 0xFFFFFFFF));
      expect(
          new Register64(0x00000000, 0x80000000)
            ..mul(new Register64(0x00000000, 0x00000004)),
          new Register64(0x00000002, 0x00000000));
      expect(
          new Register64(0x00000000, 0x80000001)
            ..mul(new Register64(0x00000000, 0x00000004)),
          new Register64(0x00000002, 0x00000004));
      expect(
          new Register64(0x80000001, 0x80000001)
            ..mul(new Register64(0x00000000, 0x00000004)),
          new Register64(0x00000006, 0x00000004));
    });

    test("neg()", () {
      expect(new Register64(0x00000000, 0x00000000)..neg(),
          new Register64(0x00000000, 0x00000000));
      expect(new Register64(0xFFFFFFFF, 0xFFFFFFFF)..neg(),
          new Register64(0x00000000, 0x00000001));
      expect(new Register64(0x50505050, 0x05050505)..neg(),
          new Register64(0xAFAFAFAF, 0xFAFAFAFB));
    });

    test("not()", () {
      expect(new Register64(0x00000000, 0x00000000)..not(),
          new Register64(0xFFFFFFFF, 0xFFFFFFFF));
      expect(new Register64(0xFFFFFFFF, 0xFFFFFFFF)..not(),
          new Register64(0x00000000, 0x00000000));
      expect(new Register64(0x50505050, 0x05050505)..not(),
          new Register64(0xAFAFAFAF, 0xFAFAFAFA));
    });

    test("and()", () {
      expect(
          new Register64(0x00000000, 0x00000000)
            ..and(new Register64(0xFFFFFFFF, 0xFFFFFFFF)),
          new Register64(0x00000000, 0x00000000));
      expect(
          new Register64(0x10203040, 0x05050505)
            ..and(new Register64(0xFFFFFFFF, 0xFFFFFFFF)),
          new Register64(0x10203040, 0x05050505));
      expect(
          new Register64(0x10203040, 0x05050505)
            ..and(new Register64(0x00000000, 0xFFFFFFFF)),
          new Register64(0x00000000, 0x05050505));
      expect(
          new Register64(0x10203040, 0x05050505)
            ..and(new Register64(0xFFFFFFFF, 0x00000000)),
          new Register64(0x10203040, 0x00000000));
    });

    test("or()", () {
      expect(
          new Register64(0x00000000, 0x00000000)
            ..or(new Register64(0xFFFFFFFF, 0xFFFFFFFF)),
          new Register64(0xFFFFFFFF, 0xFFFFFFFF));
      expect(
          new Register64(0x10203040, 0x05050505)
            ..or(new Register64(0xFFFFFFFF, 0xFFFFFFFF)),
          new Register64(0xFFFFFFFF, 0xFFFFFFFF));
      expect(
          new Register64(0x10203040, 0x05050505)
            ..or(new Register64(0x00000000, 0xFFFFFFFF)),
          new Register64(0x10203040, 0xFFFFFFFF));
      expect(
          new Register64(0x10203040, 0x05050505)
            ..or(new Register64(0xFFFFFFFF, 0x00000000)),
          new Register64(0xFFFFFFFF, 0x05050505));
    });

    test("xor()", () {
      expect(
          new Register64(0x00000000, 0x00000000)
            ..xor(new Register64(0xFFFFFFFF, 0xFFFFFFFF)),
          new Register64(0xFFFFFFFF, 0xFFFFFFFF));
      expect(
          new Register64(0x10203040, 0x05050505)
            ..xor(new Register64(0xFFFFFFFF, 0xFFFFFFFF)),
          new Register64(0xEFDFCFBF, 0xFAFAFAFA));
      expect(
          new Register64(0x10203040, 0x05050505)
            ..xor(new Register64(0x00000000, 0xFFFFFFFF)),
          new Register64(0x10203040, 0xFAFAFAFA));
      expect(
          new Register64(0x10203040, 0x05050505)
            ..xor(new Register64(0xFFFFFFFF, 0x00000000)),
          new Register64(0xEFDFCFBF, 0x05050505));
    });

    test("shiftl()", () {
      expect(new Register64(0x10203040, 0x05050505)..shiftl(0),
          new Register64(0x10203040, 0x05050505));
      expect(new Register64(0x10203040, 0x05050505)..shiftl(16),
          new Register64(0x30400505, 0x05050000));
      expect(new Register64(0x10203040, 0x05050505)..shiftl(32),
          new Register64(0x05050505, 0x00000000));
      expect(new Register64(0x10203040, 0x05050505)..shiftl(48),
          new Register64(0x05050000, 0x00000000));
      expect(new Register64(0x10203040, 0x05050505)..shiftl(64),
          new Register64(0x10203040, 0x05050505));
    });

    test("shiftr()", () {
      expect(new Register64(0x10203040, 0x05050505)..shiftr(0),
          new Register64(0x10203040, 0x05050505));
      expect(new Register64(0x10203040, 0x05050505)..shiftr(16),
          new Register64(0x00001020, 0x30400505));
      expect(new Register64(0x10203040, 0x05050505)..shiftr(32),
          new Register64(0x00000000, 0x10203040));
      expect(new Register64(0x10203040, 0x05050505)..shiftr(48),
          new Register64(0x00000000, 0x00001020));
      expect(new Register64(0x10203040, 0x05050505)..shiftr(64),
          new Register64(0x10203040, 0x05050505));
    });

    test("rotl()", () {
      expect(new Register64(0x10203040, 0x05050505)..rotl(0),
          new Register64(0x10203040, 0x05050505));
      expect(new Register64(0x10203040, 0x05050505)..rotl(16),
          new Register64(0x30400505, 0x05051020));
      expect(new Register64(0x10203040, 0x05050505)..rotl(32),
          new Register64(0x05050505, 0x10203040));
      expect(new Register64(0x10203040, 0x05050505)..rotl(48),
          new Register64(0x05051020, 0x30400505));
      expect(new Register64(0x10203040, 0x05050505)..rotl(64),
          new Register64(0x10203040, 0x05050505));
    });

    test("rotr()", () {
      expect(new Register64(0x10203040, 0x05050505)..rotr(0),
          new Register64(0x10203040, 0x05050505));
      expect(new Register64(0x10203040, 0x05050505)..rotr(16),
          new Register64(0x05051020, 0x30400505));
      expect(new Register64(0x10203040, 0x05050505)..rotr(32),
          new Register64(0x05050505, 0x10203040));
      expect(new Register64(0x10203040, 0x05050505)..rotr(48),
          new Register64(0x30400505, 0x05051020));
      expect(new Register64(0x10203040, 0x05050505)..rotr(64),
          new Register64(0x10203040, 0x05050505));
    });

    test("pack(BIG_ENDIAN)", () {
      var out = new Uint8List(64);
      new Register64(0x10203040, 0x50607080).pack(out, 0, Endian.big);
      expect(out[0], 0x10);
      expect(out[1], 0x20);
      expect(out[2], 0x30);
      expect(out[3], 0x40);
      expect(out[4], 0x50);
      expect(out[5], 0x60);
      expect(out[6], 0x70);
      expect(out[7], 0x80);
    });

    test("pack(LITTLE_ENDIAN)", () {
      var out = new Uint8List(64);
      new Register64(0x10203040, 0x50607080).pack(out, 0, Endian.little);
      expect(out[7], 0x10);
      expect(out[6], 0x20);
      expect(out[5], 0x30);
      expect(out[4], 0x40);
      expect(out[3], 0x50);
      expect(out[2], 0x60);
      expect(out[1], 0x70);
      expect(out[0], 0x80);
    });

    test("unpack(BIG_ENDIAN)", () {
      var inp = new Uint8List.fromList(
          [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80]);
      expect(new Register64()..unpack(inp, 0, Endian.big),
          new Register64(0x10203040, 0x50607080));
    });

    test("unpack(LITTLE_ENDIAN)", () {
      var inp = new Uint8List.fromList(
          [0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10]);
      expect(new Register64()..unpack(inp, 0, Endian.little),
          new Register64(0x10203040, 0x50607080));
    });

    test("pack(Uint8List.view)", () {
      var out = new Uint8List(68);
      out = new Uint8List.view(out.buffer, 2, 64);
      new Register64(0x10203040, 0x50607080).pack(out, 0, Endian.big);
      expect(out[0], 0x10);
      expect(out[1], 0x20);
      expect(out[2], 0x30);
      expect(out[3], 0x40);
      expect(out[4], 0x50);
      expect(out[5], 0x60);
      expect(out[6], 0x70);
      expect(out[7], 0x80);
    });

    test("unpack(LITTLE_ENDIAN)", () {
      var inp = new Uint8List.fromList(
          [0, 0, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0, 0]);
      inp = new Uint8List.view(inp.buffer, 2, 8);
      expect(new Register64()..unpack(inp, 0, Endian.little),
          new Register64(0x10203040, 0x50607080));
    });

    test("toString()", () {
      expect(new Register64(0x00203040, 0x00050505).toString(),
          "0020304000050505");
    });
  });

  group("Register64List:", () {
    test("Register64.from()", () {
      final list = new Register64List.from([
        [0, 1],
        [2, 3],
        [4, 5]
      ]);

      expect(list[0], new Register64(0x00000000, 0x00000001));
      expect(list[1], new Register64(0x00000002, 0x00000003));
      expect(list[2], new Register64(0x00000004, 0x00000005));
    });
  });
}
