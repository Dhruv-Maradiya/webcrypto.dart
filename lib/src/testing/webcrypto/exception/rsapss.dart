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

import 'package:webcrypto/webcrypto.dart';

import 'package:test/test.dart';

void main() {
  group('RSAPSS', () {
    late final RsaPssPrivateKey privateKey;
    late final RsaPssPublicKey publicKey;

    late Uint8List corruptedPKCS8;
    late Map<String, dynamic> corruptedJWK;
    late Map<String, dynamic> corruptedJWKWithInvalidHash;

    setUpAll(() async {
      // This is a workaround for the fact that the test framework does not
      // support async setUp functions.
      final newKeyPair = await RsaPssPrivateKey.generateKey(
          2048, BigInt.from(65537), Hash.sha256);
      privateKey = newKeyPair.privateKey;
      publicKey = newKeyPair.publicKey;

      corruptedPKCS8 = await privateKey.exportPkcs8Key();
      corruptedPKCS8[0] = 0x00; // corrupt the first byte

      corruptedJWK = await publicKey.exportJsonWebKey();
      corruptedJWK['kty'] = 'invalid'; // corrupt the alg property

      corruptedJWKWithInvalidHash = await publicKey.exportJsonWebKey();
      corruptedJWKWithInvalidHash['alg'] = 'PS512';
    });

    group('generateKey', () {
      test('modulusLength is negative', () async {
        try {
          await RsaPssPrivateKey.generateKey(
              -1, BigInt.from(65537), Hash.sha256);
        } catch (e) {
          expect(e, isA<UnsupportedError>());
          expect(
            e.toString(),
            contains('modulusLength must between 256 and 16k'),
          );
        }
      });

      test('modulusLength is zero', () async {
        try {
          await RsaPssPrivateKey.generateKey(
              0, BigInt.from(65537), Hash.sha256);
        } catch (e) {
          expect(e, isA<UnsupportedError>());
          expect(
            e.toString(),
            contains('modulusLength must between 256 and 16k'),
          );
        }
      });

      test('publicExponent is negative', () async {
        try {
          await RsaPssPrivateKey.generateKey(
              2048, BigInt.from(-1), Hash.sha256);
        } catch (e) {
          expect(e, isA<UnsupportedError>());
          expect(
            e.toString(),
            contains('publicExponent is not supported'),
          );
        }
      });

      test('publicExponent is zero', () async {
        try {
          await RsaPssPrivateKey.generateKey(2048, BigInt.from(0), Hash.sha256);
        } catch (e) {
          expect(e, isA<UnsupportedError>());
          expect(
            e.toString(),
            contains('publicExponent is not supported'),
          );
        }
      });

      test('invalid length', () async {
        try {
          await RsaPssPrivateKey.generateKey(
              32000, BigInt.from(65537), Hash.sha512);
        } catch (e) {
          expect(e, isA<UnsupportedError>());
          expect(
            e.toString(),
            contains('modulusLength must between 256 and 16k'),
          );
        }
      });
    });

    group('importKey', () {
      test('corrupted PKCS8 data', () async {
        try {
          await RsaPssPrivateKey.importPkcs8Key(Uint8List(0), Hash.sha256);
        } catch (e) {
          expect(e, isA<FormatException>());
          expect(e.toString(), contains('DECODE_ERROR'));
        }
      });

      test('corrupted JWK', () async {
        try {
          await RsaPssPublicKey.importJsonWebKey(corruptedJWK, Hash.sha256);
        } catch (e) {
          expect(e, isA<FormatException>());
          expect(e.toString(), contains('JWK property "kty" must be "RSA"'));
        }
      });

      test('invalid hash', () async {
        try {
          await RsaPssPublicKey.importJsonWebKey(
              corruptedJWKWithInvalidHash, Hash.sha256);
        } catch (e) {
          expect(e, isA<FormatException>());
          expect(e.toString(), contains('JWK property "alg" must be "PS256"'));
        }
      });
    });

    group('signBytes', () {
      test('negative saltLength', () async {
        try {
          await privateKey.signBytes(Uint8List.fromList([1, 2, 3]), -1);
        } catch (e) {
          expect(e, isA<ArgumentError>());
          expect(e.toString(), contains('must be a positive integer'));
        }
      });

      test('too large saltLength', () async {
        try {
          await privateKey.signBytes(Uint8List.fromList([1, 2, 3]), 9999);
        } catch (e) {
          expect(e, isA<OperationError>());
          expect(
            e.toString(),
            contains('routines:OPENSSL_internal:DATA_TOO_LARGE_FOR_KEY_SIZE'),
          );
        }
      });
    });

    group('signStream', () {
      test('negative saltLength', () {
        try {
          privateKey.signStream(
              Stream.fromIterable([
                Uint8List.fromList([1, 2, 3])
              ]),
              -1);
        } catch (e) {
          expect(e, isA<ArgumentError>());
          expect(e.toString(), contains('must be a positive integer'));
        }
      });
    });

    group('verifyBytes', () {
      test('negative saltLength', () {
        try {
          publicKey.verifyBytes(
              Uint8List.fromList([1, 2, 3]), Uint8List.fromList([1, 2, 3]), -1);
        } catch (e) {
          expect(e, isA<ArgumentError>());
          expect(e.toString(), contains('must be a positive integer'));
        }
      });
    });

    group('verifyStream', () {
      test('negative saltLength', () {
        try {
          publicKey.verifyStream(
              Uint8List.fromList([1, 2, 3]),
              Stream.fromIterable([
                Uint8List.fromList([1, 2, 3])
              ]),
              -1);
        } catch (e) {
          expect(e, isA<ArgumentError>());
          expect(e.toString(), contains('must be a positive integer'));
        }
      });
    });
  });
}
