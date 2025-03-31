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

import 'package:test/test.dart';
import 'package:webcrypto/webcrypto.dart';

class ExceptionTestCase<PrivateKey, PublicKey> {
  /// Name of the test case for reporting
  final String name;

  /// Operation this test case is for (e.g., 'generateKey', 'signBytes', etc.)
  final String operation;

  /// Parameters to pass to the function
  final List<dynamic> parameters;

  /// Private key for signing or deriving bits
  final PrivateKey? privateKey;

  /// Public key for verifying or deriving bits
  final PublicKey? publicKey;

  /// Message to sign or verify
  final Uint8List? message;

  /// Signature to verify
  final Uint8List? signature;

  /// Expected exception type
  final Type exceptionType;

  /// Expected error message (partial match)
  final String errorMessage;

  ExceptionTestCase({
    required this.name,
    required this.operation,
    required this.parameters,
    required this.exceptionType,
    required this.errorMessage,
    this.privateKey,
    this.publicKey,
    this.message,
    this.signature,
  });

  /// Create an instance from a JSON-like map
  static ExceptionTestCase fromJson(Map<String, dynamic> json) {
    return ExceptionTestCase(
      name: json['name'] as String,
      operation: json['operation'] as String,
      parameters: json['parameters'] as List<dynamic>,
      exceptionType: json['exceptionType'] as Type,
      errorMessage: json['errorMessage'] as String,
      privateKey: json['privateKey'],
      publicKey: json['publicKey'],
      message: (json['message'] as Uint8List?),
      signature: (json['signature'] as Uint8List?),
    );
  }
}

/// A generic test runner for asymmetric cryptography exception cases.
class ExceptionTestRunner<PrivateKey, PublicKey> {
  /// Algorithm name for reporting
  final String algorithmName;

  /// Map of test cases grouped by operation
  final Map<String, List<ExceptionTestCase>> _testCases;

  /// Function that generates a key pair
  final Future<KeyPair<PrivateKey, PublicKey>> Function(
      Object? p1, Object? p2, Object? p3) generateKeyFn;

  /// Function that signs bytes with a private key
  final Future<Uint8List> Function(
      PrivateKey key, Uint8List data, dynamic param)? signBytesFn;

  /// Function that signs a stream with a private key
  final Future<Uint8List> Function(
      PrivateKey key, Stream<List<int>> data, dynamic param)? signStreamFn;

  /// Function that verifies bytes with a public key
  final Future<bool> Function(
          PublicKey key, Uint8List signature, Uint8List data, dynamic param)?
      verifyBytesFn;

  /// Function that verifies a stream with a public key
  final Future<bool> Function(PublicKey key, Uint8List signature,
      Stream<List<int>> data, dynamic param)? verifyStreamFn;

  /// Function that derives bits using the private key and public key
  final Future<Uint8List> Function(
      PrivateKey key, dynamic length, PublicKey publicKey)? deriveBitsFn;

  /// Function that imports a private key from PKCS8 format
  final Future<PrivateKey> Function(Uint8List keyData, dynamic param)
      importPkcs8Fn;

  /// Function that imports a private key from JSON Web Key format
  final Future<PrivateKey> Function(Map<String, dynamic> jwk, dynamic param)
      importJsonWebKeyFn;

  /// Function that exports a private key to PKCS8 format
  final Future<Uint8List> Function(PrivateKey key) exportPkcs8Fn;

  /// Function that exports a private key to JSON Web Key format
  final Future<Map<String, dynamic>> Function(PrivateKey key)
      exportJsonWebKeyFn;

  ExceptionTestRunner({
    required this.algorithmName,
    required List<ExceptionTestCase<PrivateKey, PublicKey>> testCases,
    required this.generateKeyFn,
    this.signBytesFn,
    this.signStreamFn,
    this.verifyBytesFn,
    this.verifyStreamFn,
    this.deriveBitsFn,
    required this.importPkcs8Fn,
    required this.importJsonWebKeyFn,
    required this.exportPkcs8Fn,
    required this.exportJsonWebKeyFn,
  }) : _testCases = _groupTestCases(testCases);

  /// Helper method to group test cases by operation
  static Map<String, List<ExceptionTestCase>> _groupTestCases<K, P>(
      List<ExceptionTestCase<K, P>> testCases) {
    final result = <String, List<ExceptionTestCase>>{};

    for (final testCase in testCases) {
      final operation = testCase.operation;

      result.putIfAbsent(operation, () => []).add(testCase);
    }

    return result;
  }

  /// Get test cases for a specific operation
  List<ExceptionTestCase> getTestCases(String operation) {
    return _testCases[operation] ?? [];
  }

  /// Register all exception test groups and test cases synchronously
  void registerTests() {
    // Main test group for the algorithm
    group(algorithmName, () {
      // Test group for key generation tests
      final generateKeyTestCases = getTestCases('generateKey');
      if (generateKeyTestCases.isNotEmpty) {
        group('generateKey Exception', () {
          for (final testCase in generateKeyTestCases) {
            test(testCase.name, () async {
              try {
                await Function.apply(generateKeyFn, testCase.parameters);
                fail('Exception expected');
              } catch (e) {
                expect(e.runtimeType, testCase.exceptionType);
                expect(e.toString(), contains(testCase.errorMessage));
              }
            });
          }
        });
      }

      // Only register these test groups if the corresponding test cases are provided
      final importPkcs8TestCases = getTestCases('importPkcs8');
      if (importPkcs8TestCases.isNotEmpty) {
        group('importPkcs8Key Exception', () {
          for (final testCase in importPkcs8TestCases) {
            test(testCase.name, () async {
              try {
                final param = testCase.parameters[1];
                await importPkcs8Fn(testCase.parameters[0] as Uint8List, param);
                fail('Exception expected');
              } catch (e) {
                expect(e.runtimeType, testCase.exceptionType);
                expect(e.toString(), contains(testCase.errorMessage));
              }
            });
          }
        });
      }

      final importJsonWebKeyTestCases = getTestCases('importJsonWebKey');
      if (importJsonWebKeyTestCases.isNotEmpty) {
        group('importJsonWebKey Exception', () {
          for (final testCase in importJsonWebKeyTestCases) {
            test(testCase.name, () async {
              try {
                final param = testCase.parameters[1];
                await importJsonWebKeyFn(
                    testCase.parameters[0] as Map<String, dynamic>, param);
                fail('Exception expected');
              } catch (e) {
                expect(e.runtimeType, testCase.exceptionType);
                expect(e.toString(), contains(testCase.errorMessage));
              }
            });
          }
        });
      }

      final signBytesTestCases = getTestCases('signBytes');
      if (signBytesTestCases.isNotEmpty && signBytesFn != null) {
        group('signBytes Exception', () {
          for (final testCase in signBytesTestCases) {
            test(testCase.name, () async {
              try {
                final param = testCase.parameters[0];
                await signBytesFn!(
                    testCase.privateKey, testCase.message!, param);
                fail('Exception expected');
              } catch (e) {
                expect(e.runtimeType, testCase.exceptionType);
                expect(e.toString(), contains(testCase.errorMessage));
              }
            });
          }
        });
      }

      final signStreamTestCases = getTestCases('signStream');
      if (signStreamTestCases.isNotEmpty && signStreamFn != null) {
        group('signStream Exception', () {
          for (final testCase in signStreamTestCases) {
            test(testCase.name, () async {
              try {
                final param = testCase.parameters[0];
                await signStreamFn!(testCase.privateKey,
                    Stream.value(testCase.message!), param);
                fail('Exception expected');
              } catch (e) {
                expect(e.runtimeType, testCase.exceptionType);
                expect(e.toString(), contains(testCase.errorMessage));
              }
            });
          }
        });
      }

      final verifyBytesTestCases = getTestCases('verifyBytes');
      if (verifyBytesTestCases.isNotEmpty && verifyBytesFn != null) {
        group('verifyBytes Exception', () {
          for (final testCase in verifyBytesTestCases) {
            test(testCase.name, () async {
              try {
                final param = testCase.parameters[0];
                await verifyBytesFn!(testCase.publicKey, testCase.signature!,
                    testCase.message!, param);
                fail('Exception expected');
              } catch (e) {
                expect(e.runtimeType, testCase.exceptionType);
                expect(e.toString(), contains(testCase.errorMessage));
              }
            });
          }
        });
      }

      final verifyStreamTestCases = getTestCases('verifyStream');
      if (verifyStreamTestCases.isNotEmpty && verifyStreamFn != null) {
        group('verifyStream Exception', () {
          for (final testCase in verifyStreamTestCases) {
            test(testCase.name, () async {
              try {
                final param = testCase.parameters[0];
                await verifyStreamFn!(testCase.publicKey, testCase.signature!,
                    Stream.value(testCase.message!), param);
                fail('Exception expected');
              } catch (e) {
                expect(e.runtimeType, testCase.exceptionType);
                expect(e.toString(), contains(testCase.errorMessage));
              }
            });
          }
        });
      }

      final deriveBitsTestCases = getTestCases('deriveBits');
      if (deriveBitsTestCases.isNotEmpty && deriveBitsFn != null) {
        group('deriveBits Exception', () {
          for (final testCase in deriveBitsTestCases) {
            test(testCase.name, () async {
              try {
                final length = testCase.parameters[0] as int;
                await deriveBitsFn!(
                    testCase.privateKey, length, testCase.publicKey);
                fail('Exception expected');
              } catch (e) {
                expect(e.runtimeType, testCase.exceptionType);
                expect(e.toString(), contains(testCase.errorMessage));
              }
            });
          }
        });
      }
    });
  }
}
