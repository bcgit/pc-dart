// See file LICENSE for more information.

library test.digests.sm3_test;

import 'package:pointycastle/pointycastle.dart';

import '../test/runners/digest.dart';

void main() {
  runDigestTests(Digest('SM3'), [
    // Example 1, From GB/T 32905-2016
    'abc',
    '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0',
    // Example 2, From GB/T 32905-2016
    'abcd' * 16,
    'debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732',
  ]);
}
