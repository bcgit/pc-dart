import 'abstract.dart'
  if (dart.library.io) 'native.dart'
  if (dart.library.js) 'web.dart';

abstract class Platform {
  static Platform get instance => getPlatform();

  const Platform();

  String get platform;

  bool get isNative;
}