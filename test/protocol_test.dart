import 'dart:convert';
import 'dart:io';
import 'package:cbor/cbor.dart';
import 'package:fido2/fido2_server.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:canokey_webauthn_demo/protocol.dart';

void main() {
  final fixture =
      jsonDecode(File('test/fixtures/webauthn.json').readAsStringSync())
          as Map<String, dynamic>;
  final config = CoseConfiguration(
    sm2: Sm2Configuration(algorithm: -65537, curve: -65537),
  );
  setUpAll(() => RustCrypto.initialize());

  test('binary formats and invalid input', () {
    for (final format in ['hex', 'b64', 'b64u']) {
      expect(decodeBinary(binary([0, 255, 128, 1], format), format), [
        0,
        255,
        128,
        1,
      ]);
    }
    expect(() => decodeBinary('abc', 'hex'), throwsFormatException);
    expect(
      () => inspect('oops', 'Credential JSON', 'b64u', 'hex', config),
      throwsFormatException,
    );
  });

  for (final v in fixture['vectors'] as List) {
    test(
      '${v['algorithm']}: registration, storage, assertion and inspector',
      () {
        final keyBytes = (v['key'] as List).cast<int>();
        final key = CoseKey.parse(switch (v['algorithm']) {
          'es256' || 'sm2' => {
            1: 2,
            3: v['alg'],
            -1: v['algorithm'] == 'sm2' ? -65537 : 1,
            -2: keyBytes.sublist(1, 33),
            -3: keyBytes.sublist(33),
          },
          'ed25519' => {1: 1, 3: v['alg'], -1: 6, -2: keyBytes},
          _ => {1: 7, 3: v['alg'], -1: keyBytes},
        }, configuration: config);
        final challenge = (fixture['challenge'] as List).cast<int>();
        final authBytes = (fixture['authenticatorData'] as List).cast<int>();
        final registrationAuth = [
          ...authBytes.sublist(0, 32),
          65,
          0,
          0,
          0,
          0,
          ...List.filled(16, 0),
          0,
          1,
          7,
          ...cbor.encode(key.toCborMap()),
        ];
        final attestation = cbor.encode(
          CborMap({
            CborString('fmt'): CborString('none'),
            CborString('attStmt'): CborMap({}),
            CborString('authData'): CborBytes(registrationAuth),
          }),
        );
        final registration = <String, dynamic>{
          'id': b64([7]),
          'rawId': b64([7]),
          'type': 'public-key',
          'response': {
            'clientDataJSON': b64(
              utf8.encode(
                jsonEncode({
                  'type': 'webauthn.create',
                  'challenge': b64(challenge),
                  'origin': 'https://example.com',
                }),
              ),
            ),
            'attestationObject': b64(attestation),
          },
        };
        final server = Fido2Server(
          Fido2Config(
            rpId: 'example.com',
            signatureAlgorithms: [v['alg']],
            cose: config,
          ),
        );
        final registered = server.registerComplete(
          registration,
          expectedChallenge: challenge,
          offeredAlgorithms: [v['alg']],
          userHandle: [1],
        );
        final saved = SavedCredential(
          rpId: 'example.com',
          username: 'test',
          created: '2026-09-07',
          credential: registered,
          sm2: key is SM2 ? config.sm2 : null,
          transports: ['usb', 'hybrid'],
        );
        final restored = SavedCredential.fromJson(
          jsonDecode(jsonEncode(saved.toJson())),
        );
        expect(restored.credential.publicKey.algorithmId, v['alg']);
        expect(restored.transports, ['usb', 'hybrid']);
        final assertion = <String, dynamic>{
          'id': b64([7]),
          'rawId': b64([7]),
          'type': 'public-key',
          'response': {
            'clientDataJSON': b64(
              (fixture['clientDataJSON'] as List).cast<int>(),
            ),
            'authenticatorData': b64(authBytes),
            'signature': b64((v['signature'] as List).cast<int>()),
            'userHandle': b64([1]),
          },
        };
        expect(
          server.authenticateComplete(
            assertion,
            credential: restored.credential,
            expectedChallenge: challenge,
          ),
          1,
        );
        expect(
          inspect(
            jsonEncode(registration),
            'Credential JSON',
            'b64u',
            'hex',
            config,
          ),
          isA<Map>(),
        );
        expect(
          inspect(
            jsonEncode(assertion),
            'Credential JSON',
            'b64u',
            'hex',
            config,
          ),
          isA<Map>(),
        );
        final signature = (v['signature'] as List).cast<int>().toList();
        signature[0] ^= 1;
        (assertion['response'] as Map)['signature'] = b64(signature);
        expect(
          () => server.authenticateComplete(
            assertion,
            credential: restored.credential,
            expectedChallenge: challenge,
          ),
          throwsA(anything),
        );
      },
    );
  }
}
