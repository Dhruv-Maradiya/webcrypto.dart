// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'dart:typed_data';

import 'package:webcrypto/src/testing/utils/exception_testrunner.dart';
import 'package:webcrypto/src/testing/utils/utils.dart';
import 'package:webcrypto/webcrypto.dart';

Future<ExceptionTestRunner> getExceptionRunner() async {
  final keyPair = await RsaPssPrivateKey.generateKey(
    2048,
    BigInt.from(65537),
    Hash.sha256,
  );
  final plaintext = Uint8List.fromList([1, 2, 3, 4]);
  final signature = await keyPair.privateKey.signBytes(plaintext, 32);

  final pkcs8Key = await keyPair.privateKey.exportPkcs8Key();
  final jwk = await keyPair.privateKey.exportJsonWebKey();

  final List<ExceptionTestCase> testCases = [
    ExceptionTestCase(
      operation: 'generateKey',
      name: 'modulusLength is negative',
      parameters: [-1, BigInt.from(65537), Hash.sha256],
      exceptionType: UnsupportedError,
      errorMessage: 'modulusLength must between 256 and 16k',
    ),
    ExceptionTestCase(
      operation: 'generateKey',
      name: 'modulusLength is zero',
      parameters: [0, BigInt.from(65537), Hash.sha256],
      exceptionType: UnsupportedError,
      errorMessage: 'modulusLength must between 256 and 16k',
    ),
    ExceptionTestCase(
      operation: 'generateKey',
      name: 'publicExponent is negative',
      parameters: [2048, BigInt.from(-1), Hash.sha256],
      exceptionType: UnsupportedError,
      errorMessage: 'publicExponent is not supported',
    ),
    ExceptionTestCase(
      operation: 'generateKey',
      name: 'publicExponent is zero',
      parameters: [2048, BigInt.from(0), Hash.sha256],
      exceptionType: UnsupportedError,
      errorMessage: 'publicExponent is not supported',
    ),
    ExceptionTestCase(
      operation: 'generateKey',
      name: 'invalid length',
      parameters: [32000, BigInt.from(65537), Hash.sha512],
      exceptionType: UnsupportedError,
      errorMessage: 'modulusLength must between 256 and 16k',
    ),
    ExceptionTestCase<RsaPssPrivateKey, RsaPssPublicKey>(
      operation: 'signBytes',
      name: 'negative saltLength',
      privateKey: keyPair.privateKey,
      message: plaintext,
      parameters: [-1],
      exceptionType: ArgumentError,
      errorMessage: 'must be a positive integer',
    ),
    ExceptionTestCase<RsaPssPrivateKey, RsaPssPublicKey>(
      operation: 'signBytes',
      name: 'too large saltLength',
      privateKey: keyPair.privateKey,
      message: plaintext,
      parameters: [9999],
      exceptionType: OperationError,
      errorMessage: 'routines:OPENSSL_internal:DATA_TOO_LARGE_FOR_KEY_SIZE',
    ),
    ExceptionTestCase<RsaPssPrivateKey, RsaPssPublicKey>(
      operation: 'signStream',
      name: 'negative saltLength',
      privateKey: keyPair.privateKey,
      message: plaintext,
      parameters: [-1],
      exceptionType: ArgumentError,
      errorMessage: 'must be a positive integer',
    ),
    ExceptionTestCase<RsaPssPrivateKey, RsaPssPublicKey>(
      operation: 'verifyBytes',
      name: 'negative saltLength',
      publicKey: keyPair.publicKey,
      signature: signature,
      message: plaintext,
      parameters: [-1],
      exceptionType: ArgumentError,
      errorMessage: 'must be a positive integer',
    ),
    ExceptionTestCase<RsaPssPrivateKey, RsaPssPublicKey>(
      operation: 'verifyStream',
      name: 'negative saltLength',
      publicKey: keyPair.publicKey,
      signature: signature,
      message: plaintext,
      parameters: [-1],
      exceptionType: ArgumentError,
      errorMessage: 'must be a positive integer',
    ),
    ExceptionTestCase<RsaPssPrivateKey, RsaPssPublicKey>(
      operation: 'importPkcs8',
      name: 'corrupted PKCS8 data',
      parameters: [
        flipFirstBits(pkcs8Key),
        Hash.sha256,
      ],
      exceptionType: FormatException,
      errorMessage: 'DECODE_ERROR',
    ),
    ExceptionTestCase<RsaPssPrivateKey, RsaPssPublicKey>(
      operation: 'importJsonWebKey',
      name: 'corrupted JWK',
      parameters: [
        {...jwk, 'kty': 'invalid'},
        Hash.sha256,
      ],
      exceptionType: FormatException,
      errorMessage: 'JWK property',
    ),
    ExceptionTestCase<RsaPssPrivateKey, RsaPssPublicKey>(
      operation: 'importJsonWebKey',
      name: 'invalid hash',
      parameters: [
        {...jwk, 'alg': 'PS256'},
        Hash.sha512,
      ],
      exceptionType: FormatException,
      errorMessage: 'JWK property "alg" must be "PS512"',
    ),
  ];

  return ExceptionTestRunner(
    algorithmName: 'RsaPssPrivateKey',
    testCases: testCases,
    generateKeyFn: (keySize, exponent, hash) => RsaPssPrivateKey.generateKey(
        keySize as int, exponent as BigInt, hash as Hash),
    signBytesFn: (key, data, param) => key.signBytes(data, param ?? 0),
    signStreamFn: (key, data, param) => key.signStream(data, param ?? 0),
    verifyBytesFn: (key, sig, data, param) =>
        key.verifyBytes(sig, data, param ?? 0),
    verifyStreamFn: (key, sig, data, param) =>
        key.verifyStream(sig, data, param ?? 0),
    importPkcs8Fn: (keyData, hash) =>
        RsaPssPrivateKey.importPkcs8Key(keyData, hash as Hash),
    importJsonWebKeyFn: (jwk, hash) =>
        RsaPssPrivateKey.importJsonWebKey(jwk, hash as Hash),
    exportPkcs8Fn: (key) => key.exportPkcs8Key(),
    exportJsonWebKeyFn: (key) => key.exportJsonWebKey(),
  );
}

void main() async {
  // Register all test groups synchronously upfront
  final runner = await getExceptionRunner();
  runner.registerTests();
}
