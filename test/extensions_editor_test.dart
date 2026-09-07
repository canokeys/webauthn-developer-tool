import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:canokey_webauthn_demo/extensions_editor.dart';

void main() {
  testWidgets('PRF controls share JSON state and preserve unrelated fields', (
    tester,
  ) async {
    final controller = TextEditingController(
      text: '{"credProps":true,"custom":{"value":1}}',
    );
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: SingleChildScrollView(
            child: ValueListenableBuilder(
              valueListenable: controller,
              builder: (context, value, child) => ExtensionsEditor(
                controller: controller,
                create: true,
                enabled: true,
                credentialIds: const [],
              ),
            ),
          ),
        ),
      ),
    );
    await tester.ensureVisible(find.text('Pseudo-random function (PRF)'));
    await tester.tap(find.text('Pseudo-random function (PRF)'));
    await tester.pumpAndSettle();
    final first = find.byWidgetPredicate(
      (w) =>
          w is TextField && w.decoration?.labelText == 'PRF first · Base64URL',
    );
    final second = find.byWidgetPredicate(
      (w) =>
          w is TextField && w.decoration?.labelText == 'PRF second · Base64URL',
    );
    await tester.enterText(first, 'AQID');
    await tester.pump();
    await tester.enterText(second, 'BA');
    await tester.pump();
    expect(jsonDecode(controller.text)['prf']['eval'], {
      'first': 'AQID',
      'second': 'BA',
    });
    expect(jsonDecode(controller.text)['custom'], {'value': 1});
    await tester.enterText(first, '');
    await tester.pump();
    expect(jsonDecode(controller.text)['prf'], {});
    expect((tester.widget(second) as TextField).enabled, false);
    controller.text = '{"credProps":false,"prf":{"eval":{"first":"CQ"}}}';
    await tester.pump();
    expect((tester.widget(first) as TextField).controller!.text, 'CQ');
    controller.text = '{"prf":{"eval":42}}';
    await tester.pump();
    await tester.enterText(first, 'AQ');
    await tester.pump();
    expect(jsonDecode(controller.text)['prf']['eval'], {'first': 'AQ'});
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox());
    controller.dispose();
  });
}
