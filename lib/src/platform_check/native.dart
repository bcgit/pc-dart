import 'dart:io' as io;

import 'platform_check.dart';

class PlatformIO extends Platform {
  static final PlatformIO instance = PlatformIO();

  const PlatformIO();

  @override
  String get platform {
    if (io.Platform.isAndroid) return 'Android';
    if (io.Platform.isIOS) return 'iOS';
    if (io.Platform.isWindows) return 'Windows';
    if (io.Platform.isLinux) return 'Linux';
    if (io.Platform.isFuchsia) return 'Fuchsia';
    if (io.Platform.isMacOS) return 'MacOS';

    return 'native';
  }

  @override
  bool get isNative => true;
}

Platform getPlatform() => PlatformIO.instance;