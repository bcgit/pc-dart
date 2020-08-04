// See file LICENSE for more information.

library test.digests.blake2b_test;

import 'package:pointycastle/pointycastle.dart';

import '../test/digest_tests.dart';

void main() {
  runDigestTests(Digest('Blake2b'), [
    '',
    '786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce',
    'Lorem ipsum dolor sit amet, consectetur adipiscing elit...',
    'b26dc06e2a96f3a2d16313b8633e79c438317ba399ed143aa0a695c2c14df01bf7870ad2ee09b3ef7f0d36bba5c98541cbce3c6e802790b402534f757d2085d3',
    'En un lugar de La Mancha, de cuyo nombre no quiero acordarme...',
    'c782dabd3cabf2e74f2b6e9854fc6f274583cb77003e20625ec19efad78993480c237594841cef9933ac7a675a526426460d87bc0ef4538ed08d0e2744a22900',
    'Lorem ipsum dolor sit amet, ex has ignota maluisset persecuti. Cum ad integre splendide adipiscing. An sit ipsum possim, dicunt ',
    'ee370c9780381c360feeedc04fff3caa17687cde31e8a541d0a0053c3b92c0195d0f64e27126cba2e79f1b007f3ec9ab66f5fd9bca416654a05cfd94cb8da2be',
    'Lorem ipsum dolor sit amet, ex has ignota maluisset persecuti. Cum ad integre splendide adipiscing. An sit ipsum possim, dicunt eirmod habemus mea at, in sea alii dolorem deterruisset. An habeo fabellas facilisis eum, aperiri imperdiet definitiones eum no. Aeque delicata eos et. Fierent platonem cum id.',
    '79ca22680c4a9b72299eb22d173222b309d9f2b90f9f16bc170a143482d62b23029b6712758bf6135659adeeeaf8ad472b746674b5e10b7a4cb6b803b88c19db',
  ]);
}
