import 'package:flutter/material.dart';
import 'package:web/web.dart' as web;

class PasskeyAutofill extends StatelessWidget {
  const PasskeyAutofill({super.key});

  @override
  Widget build(BuildContext context) => SizedBox(
    height: 48,
    // Flutter's semantics text fields override autocomplete; keep this native.
    child: HtmlElementView.fromTagName(
      tagName: 'input',
      onElementCreated: (element) {
        final input = element as web.HTMLInputElement;
        input
          ..type = 'text'
          ..name = 'username'
          ..autocomplete = 'username webauthn'
          ..placeholder = 'Passkey autofill'
          ..className = 'passkey-autofill'
          ..setAttribute('aria-label', 'Passkey autofill');
      },
    ),
  );
}
