// See file LICENSE for more information.

/**
 * This is the API specification library for the Pointy Castle project.
 *
 * It declares all abstract types used by the Pointy Castle library.
 * In addition, it implements the factories mechanism that allows
 * users to instantiate algorithms by their standard name.
 */
library pointycastle.api;

import "dart:typed_data";

import "src/registry/registry.dart";

part "src/api/algorithm.dart";
part "src/api/asymmetric_block_cipher.dart";
part "src/api/asymmetric_key.dart";
part "src/api/asymmetric_key_pair.dart";
part "src/api/asymmetric_key_parameter.dart";
part "src/api/block_cipher.dart";
part "src/api/cipher_parameters.dart";
part "src/api/digest.dart";
part "src/api/key_derivator.dart";
part "src/api/key_generator.dart";
part "src/api/key_generator_parameters.dart";
part "src/api/key_parameter.dart";
part "src/api/mac.dart";
part "src/api/padded_block_cipher.dart";
part "src/api/padded_block_cipher_parameters.dart";
part "src/api/padding.dart";
part "src/api/parameters_with_iv.dart";
part "src/api/parameters_with_random.dart";
part "src/api/private_key.dart";
part "src/api/private_key_parameter.dart";
part "src/api/public_key.dart";
part "src/api/public_key_parameter.dart";
part "src/api/registry_factory_exception.dart";
part "src/api/secure_random.dart";
part "src/api/signature.dart";
part "src/api/signer.dart";
part "src/api/stream_cipher.dart";
