import 'dart:convert';
import 'dart:io';

import 'package:cbor/cbor.dart';
import 'package:fido2/fido2_server.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:canokey_webauthn_demo/protocol.dart';

void main() {
  setUpAll(() => RustCrypto.initialize());

  Map<String, dynamic> fixture() =>
      jsonDecode(File('test/fixtures/canokey-packed.json').readAsStringSync())
          as Map<String, dynamic>;

  Fido2Server server() => Fido2Server(
    Fido2Config(
      rpId: 'dev.canokeys.org',
      origins: {'https://dev.canokeys.org'},
      signatureAlgorithms: [-7],
      requireUserVerification: true,
    ),
  );

  final challenge = unb64('UZyIWapBC6hYM-4Trb-tvn5dIUn0DLGZ18mhw4Hyg_8');

  test('CanoKey packed certificate attestation completes registration', () {
    final credential = fixture();
    final record = server().registerComplete(
      credential,
      expectedChallenge: challenge,
      offeredAlgorithms: [-7],
      userHandle: [1],
    );
    expect(b64(record.id), credential['rawId']);
    expect(record.publicKey.algorithmId, -7);
    expect(record.signCount, 190);
  });

  test('CanoKey packed registration rejects a tampered signature', () {
    final credential = fixture();
    final response = credential['response'] as Map<String, dynamic>;
    final object = cbor.decode(unb64(response['attestationObject'])) as CborMap;
    final statement = object[CborString('attStmt')] as CborMap;
    final signature = List<int>.from(
      (statement[CborString('sig')] as CborBytes).bytes,
    );
    signature[signature.length - 1] ^= 1;
    final modified = CborMap({
      ...object,
      CborString('attStmt'): CborMap({
        ...statement,
        CborString('sig'): CborBytes(signature),
      }),
    });
    response['attestationObject'] = b64(cbor.encode(modified));
    expect(
      () => server().registerComplete(
        credential,
        expectedChallenge: challenge,
        offeredAlgorithms: [-7],
      ),
      throwsA(isA<CryptoException>()),
    );
  });
}
