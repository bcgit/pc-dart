import 'platform_check.dart';

class PlatformGeneric extends Platform {
  static final PlatformGeneric instance = PlatformGeneric();

  const PlatformGeneric();

  @override
  bool get isNative => false;

  @override
  String get platform => 'web';
}

Platform getPlatform() => PlatformGeneric.instance;
