@TestOn('js')
import 'package:pointycastle/export.dart';
import 'package:pointycastle/src/platform_check/platform_check.dart';
import 'package:test/test.dart';

/// Argon2 must fail in the js environment
void main() {
  group('Argon2BytesGenerator', () {
    test('must emit PlatformException', () {
      expect(() {
        Argon2BytesGenerator();
      }, throwsA(TypeMatcher<PlatformException>()));
    });
  });
}
