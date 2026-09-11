import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fido2/fido2_server.dart';
import 'package:canokey_webauthn_demo/inspector_panel.dart';
import 'package:canokey_webauthn_demo/protocol.dart';

void main() {
  final raw = File('test/fixtures/canokey-packed.json').readAsStringSync();
  final config = CoseConfiguration();

  test('nested certificate bytes follow the selected output encoding', () {
    for (final format in ['hex', 'b64', 'b64u']) {
      final result =
          inspect(raw, 'Credential JSON', 'b64u', format, config) as Map;
      final certificate = result['attestationObject']['attStmt']['x5c'][0];
      expect(certificate, isA<String>());
      expect(decodeBinary(certificate, format).take(4), [48, 130, 1, 183]);
      expect(result.containsKey('credential'), false);
    }
  });

  test(
    'raw response, copied envelope and exported report decode identically',
    () {
      final credential = jsonDecode(raw);
      final expected = inspect(raw, 'Credential JSON', 'b64u', 'hex', config);
      for (final envelope in [
        {'credential': credential, 'decoded': expected},
        {'operation': 'create', 'response': credential, 'verified': true},
      ]) {
        expect(
          inspect(
            jsonEncode(envelope),
            'Credential JSON',
            'b64u',
            'hex',
            config,
          ),
          expected,
        );
      }
    },
  );

  test('a broken field preserves other fields and identifies the failure', () {
    final credential = jsonDecode(raw);
    credential['response']['clientDataJSON'] = 'invalid!';
    final result =
        inspect(
              jsonEncode(credential),
              'Credential JSON',
              'b64u',
              'hex',
              config,
            )
            as Map;
    expect(result['decodeErrors'], contains('clientDataJSON'));
    expect(result['attestationObject']['fmt'], 'packed');
  });

  testWidgets(
    'expanded signatures and certificates wrap within narrow layouts',
    (tester) async {
      await tester.binding.setSurfaceSize(const Size(360, 800));
      addTearDown(() => tester.binding.setSurfaceSize(null));
      final signature = List.filled(144, 'a').join();
      final certificate = List.filled(1200, 'b').join();
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SingleChildScrollView(
              child: DecodedDataView(
                value: {
                  'attStmt': {
                    'alg': -7,
                    'sig': signature,
                    'x5c': [certificate],
                  },
                },
              ),
            ),
          ),
        ),
      );
      for (final label in ['attStmt', 'sig', 'x5c', '0']) {
        await tester.ensureVisible(find.text(label));
        await tester.tap(find.text(label));
        await tester.pumpAndSettle();
        expect(tester.takeException(), isNull);
      }
      for (final text in [signature, certificate]) {
        final size = tester.getSize(find.text(text));
        expect(size.width, lessThanOrEqualTo(360));
        expect(size.height, greaterThan(20));
        expect(size.height, lessThan(2000));
      }
    },
  );

  testWidgets('SM2 inputs have separate vertical spacing', (tester) async {
    await tester.pumpWidget(
      const MaterialApp(home: Scaffold(body: InspectorPanel())),
    );
    await tester.tap(find.text('SM2 decoding profile'));
    await tester.pumpAndSettle();
    final fields = find.byType(TextField);
    final algorithm = tester.getRect(fields.at(1));
    final curve = tester.getRect(fields.at(2));
    expect(curve.top - algorithm.bottom, greaterThanOrEqualTo(16));
    expect(tester.takeException(), isNull);
  });

  testWidgets(
    'manual edits mark results stale and formatting uses the decoded snapshot',
    (tester) async {
      await tester.pumpWidget(
        const MaterialApp(home: Scaffold(body: InspectorPanel())),
      );
      final input = find.byType(TextField).first;
      await tester.enterText(input, raw);
      await tester.tap(find.text('Decode'));
      await tester.pumpAndSettle();
      expect(find.text('credentialInfo'), findsOneWidget);
      expect(find.text('Input encoding'), findsNothing);
      await tester.enterText(input, 'not json');
      await tester.pump();
      expect(
        find.text('Input changed. Decode again to update the result.'),
        findsOneWidget,
      );
      await tester.ensureVisible(find.text('b64'));
      await tester.tap(find.text('b64'));
      await tester.pumpAndSettle();
      expect(find.text('credentialInfo'), findsOneWidget);
      expect(find.textContaining('FormatException'), findsNothing);
      await tester.ensureVisible(find.text('Decode'));
      await tester.tap(find.text('Decode'));
      await tester.pumpAndSettle();
      expect(find.text('credentialInfo'), findsNothing);
      expect(find.textContaining('FormatException'), findsOneWidget);
    },
  );
}
