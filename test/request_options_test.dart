import 'package:flutter_test/flutter_test.dart';
import 'package:canokey_webauthn_demo/request_options.dart';
import 'package:canokey_webauthn_demo/protocol.dart';

void main() {
  test(
    'compatible registration extensions include PRF evaluation at creation',
    () {
      final options = <String, dynamic>{
        'extensions': {
          'credProps': true,
          'minPinLength': true,
          'credentialProtectionPolicy': 'userVerificationRequired',
          'enforceCredentialProtectionPolicy': true,
          'largeBlob': {'support': 'required'},
          'prf': {
            'eval': {'first': 'AQID', 'second': 'BA'},
          },
        },
      };
      expect(
        () => validateRequestExtensions('create', options),
        returnsNormally,
      );
      expect(
        () => validateRequestExtensions('get', options),
        throwsFormatException,
      );
    },
  );
  test(
    'largeBlob write accepts empty bytes but requires exactly one credential',
    () {
      final options = <String, dynamic>{
        'allowCredentials': [
          {'id': 'AQ'},
        ],
        'extensions': {
          'largeBlob': {'write': ''},
        },
      };
      expect(() => validateRequestExtensions('get', options), returnsNormally);
      options['allowCredentials'] = [];
      expect(
        () => validateRequestExtensions('get', options),
        throwsFormatException,
      );
      options['extensions'] = {
        'largeBlob': {'read': true, 'write': 'AQ'},
      };
      expect(
        () => validateRequestExtensions('get', options),
        throwsFormatException,
      );
    },
  );
  test('PRF per-credential inputs bind to allowCredentials', () {
    final options = <String, dynamic>{
      'allowCredentials': [
        {'id': 'AQ'},
      ],
      'extensions': {
        'prf': {
          'evalByCredential': {
            'AQ': {'first': '', 'second': 'AQ'},
          },
        },
      },
    };
    expect(() => validateRequestExtensions('get', options), returnsNormally);
    expect(
      () => validateRequestExtensions('create', options),
      throwsFormatException,
    );
    options['allowCredentials'] = [
      {'id': 'Ag'},
    ];
    expect(
      () => validateRequestExtensions('get', options),
      throwsFormatException,
    );
  });
  test(
    'PRF and credential protection reject incomplete or malformed input',
    () {
      for (final ext in [
        {
          'prf': {
            'eval': {'second': 'AQ'},
          },
        },
        {
          'prf': {
            'eval': {'first': 'not hex!?'},
          },
        },
        {'enforceCredentialProtectionPolicy': true},
        {'credentialProtectionPolicy': 'required'},
        {'credProps': 'true'},
      ]) {
        expect(
          () => validateRequestExtensions('create', {'extensions': ext}),
          throwsFormatException,
        );
      }
    },
  );
  test(
    'extension output rendering preserves false results and binary lengths',
    () {
      final original = {
        'prf': {
          'enabled': false,
          'results': {'first': 'AP8', 'second': ''},
        },
        'largeBlob': {'written': false, 'blob': 'AQID'},
        'credProps': {'rk': false},
      };
      final output = inspectClientExtensions(original, 'hex');
      expect(output['prf']['enabled'], false);
      expect(output['prf']['results']['first'], {
        'byteLength': 2,
        'value': '00ff',
      });
      expect(output['prf']['results']['second'], {
        'byteLength': 0,
        'value': '',
      });
      expect(output['largeBlob']['written'], false);
      expect(original['largeBlob']!['blob'], 'AQID');
    },
  );
}
