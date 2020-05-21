// See file LICENSE for more information.

library pointycastle.test.digests.sha3_test;

import "package:pointycastle/pointycastle.dart";

import "../test/digest_tests.dart";

void main() {
  runDigestTests(new Digest("SHA-3/512"), [
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",
    "ac60af5cf659dcb3df7ad078a3ea92a0be21b49ab4ba82b4b7bed3734f6445019b860ffa4b25555b3666bb75716f699566967f7dff3b6b8aa89754c059035caf",
    "En un lugar de La Mancha, de cuyo nombre no quiero acordarme...",
    "c31849ce2794f05ec01cbbd6760ab2b9dbfc5a7ce7482eee934fe6818d74d3c54f3234fc935dcd1cfe1bc17f68e14ed01d3035c90214650d3740accd5860cb18",
  ]);

  runDigestTests(new Digest("SHA-3/384"), [
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",
    "bcd5faf4aa3485814bd2181d107e0bd0ac103855380a2148b8e66f1795a62331d890b60836a00a53950f66963b199c14",
  ]);

  runDigestTests(new Digest("SHA-3/288"), [
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",
    "27a8bf18a7e801e5d2acb3da4535d9fd241c36d5eee464bcd91890b465710cd3650c8b1e",
  ]);

  runDigestTests(new Digest("SHA-3/256"), [
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",
    "21db045624a9cc36738c01429ef0c87df055e8ba3b71ba809d0b9126c47df47c",
  ]);

  runDigestTests(new Digest("SHA-3/224"), [
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",
    "adbce0aaa3f486fcd21638f7e5c500c687b34581195ef557e940ef60",
  ]);
}
