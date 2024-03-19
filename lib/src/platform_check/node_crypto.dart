/// Wrapper for needed NodeJS Crypto library function and require.
library nodecryto;

import 'dart:js_interop';
import 'dart:js_interop_unsafe';

@JS()
external JSObject require(String id);

@JS()
@staticInterop
class NodeCrypto {
  static JSAny randomFillSync(JSAny buf) {
    final crypto = require('crypto');
    return crypto.callMethod('randomFillSync'.toJS, buf);
  }
}
