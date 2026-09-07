import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:fido2/fido2_server.dart';
import 'protocol.dart';
import 'request_options.dart';

/// Edits the JSON controller directly so form controls and advanced JSON share
/// a single source of truth, including fields unknown to the form.
class ExtensionsEditor extends StatefulWidget {
  final TextEditingController controller;
  final bool create;
  final bool enabled;
  final List<String> credentialIds;
  const ExtensionsEditor({
    super.key,
    required this.controller,
    required this.create,
    required this.enabled,
    required this.credentialIds,
  });
  @override
  State<ExtensionsEditor> createState() => _ExtensionsEditorState();
}

class _ExtensionsEditorState extends State<ExtensionsEditor> {
  final fields = <String, TextEditingController>{};
  @override
  void dispose() {
    for (final controller in fields.values) {
      controller.dispose();
    }
    super.dispose();
  }

  Map<String, dynamic> get data =>
      jsonDecode(widget.controller.text) as Map<String, dynamic>;
  void update(String key, Object? value) {
    final next = data;
    if (value == null) {
      next.remove(key);
    } else {
      next[key] = value;
    }
    widget.controller.text = pretty(next);
  }

  void prfValue(String name, String text, {String? credential}) {
    Map<String, dynamic> object(Object? value) =>
        value is Map ? Map<String, dynamic>.from(value) : {};
    final prf = object(data['prf']);
    final entries = object(prf['evalByCredential']);
    final values = object(
      credential == null ? prf['eval'] : entries[credential],
    );
    if (text.isEmpty) {
      values.remove(name);
    } else {
      values[name] = text;
    }
    if (!values.containsKey('first')) values.remove('second');
    if (credential == null) {
      if (values.isEmpty) {
        prf.remove('eval');
      } else {
        prf['eval'] = values;
      }
    } else {
      if (values.isEmpty) {
        entries.remove(credential);
      } else {
        entries[credential] = values;
      }
      if (entries.isEmpty) {
        prf.remove('evalByCredential');
      } else {
        prf['evalByCredential'] = entries;
      }
    }
    update('prf', prf);
  }

  Widget toggle(
    String label,
    bool value,
    ValueChanged<bool> action, {
    bool enabled = true,
  }) => SwitchListTile(
    dense: true,
    contentPadding: EdgeInsets.zero,
    title: Text(label, style: const TextStyle(fontSize: 15)),
    value: value,
    onChanged: widget.enabled && enabled ? action : null,
  );
  Widget select(
    String label,
    String value,
    List<String> options,
    ValueChanged<String> action,
  ) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 8),
    child: DropdownButtonFormField<String>(
      key: ValueKey('$label/$value'),
      initialValue: options.contains(value) ? value : 'unspecified',
      isExpanded: true,
      decoration: InputDecoration(labelText: label),
      items: options
          .map(
            (v) => DropdownMenuItem(
              value: v,
              child: Text(
                v,
                overflow: TextOverflow.ellipsis,
                style: const TextStyle(fontSize: 14),
              ),
            ),
          )
          .toList(),
      onChanged: widget.enabled ? (v) => action(v!) : null,
    ),
  );
  Widget binaryField(
    String label,
    String name,
    String value,
    ValueChanged<String> action, {
    bool enabled = true,
  }) {
    final controller = fields.putIfAbsent(
      name,
      () => TextEditingController(text: value),
    );
    if (controller.text != value) controller.text = value;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: TextField(
        controller: controller,
        enabled: widget.enabled && enabled,
        onChanged: action,
        style: const TextStyle(fontFamily: 'monospace', fontSize: 14),
        decoration: InputDecoration(
          labelText: label,
          suffixIcon: IconButton(
            tooltip: 'Generate $label',
            onPressed: widget.enabled && enabled
                ? () => action(b64(RustCrypto.randomBytes(32)))
                : null,
            icon: const Icon(Icons.refresh, size: 18),
          ),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    Map<String, dynamic> ext;
    try {
      ext = data;
    } catch (_) {
      return const Text(
        'Correct the extension JSON to edit these fields.',
        style: TextStyle(fontSize: 14, color: Colors.red),
      );
    }
    final blob = ext['largeBlob'] is Map
        ? ext['largeBlob'] as Map
        : <String, dynamic>{};
    final prf = ext['prf'] is Map ? ext['prf'] as Map : <String, dynamic>{};
    final eval = prf['eval'] is Map ? prf['eval'] as Map : <String, dynamic>{};
    final byCredential = prf['evalByCredential'] is Map
        ? prf['evalByCredential'] as Map
        : <String, dynamic>{};
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        if (widget.create) ...[
          toggle(
            'Credential properties (credProps)',
            ext['credProps'] == true,
            (v) => update('credProps', v ? true : null),
          ),
          toggle(
            'Minimum PIN length (minPinLength)',
            ext['minPinLength'] == true,
            (v) => update('minPinLength', v ? true : null),
          ),
          select(
            'Credential protection (credProtect)',
            ext['credentialProtectionPolicy']?.toString() ?? 'unspecified',
            ['unspecified', ...credentialProtectionPolicies],
            (v) {
              final next = data;
              if (v == 'unspecified') {
                next.remove('credentialProtectionPolicy');
                next.remove('enforceCredentialProtectionPolicy');
              } else {
                next['credentialProtectionPolicy'] = v;
              }
              widget.controller.text = pretty(next);
            },
          ),
          toggle(
            'Enforce credential protection',
            ext['enforceCredentialProtectionPolicy'] == true,
            (v) => update('enforceCredentialProtectionPolicy', v),
            enabled: ext.containsKey('credentialProtectionPolicy'),
          ),
        ],
        select(
          'Large blob (largeBlob)',
          widget.create
              ? blob['support']?.toString() ?? 'unspecified'
              : blob.containsKey('write')
              ? 'write'
              : blob['read'] == true
              ? 'read'
              : 'unspecified',
          widget.create
              ? ['unspecified', 'preferred', 'required']
              : ['unspecified', 'read', 'write'],
          (v) => update(
            'largeBlob',
            v == 'unspecified'
                ? null
                : widget.create
                ? {'support': v}
                : v == 'read'
                ? {'read': true}
                : {'write': ''},
          ),
        ),
        if (!widget.create && blob.containsKey('write'))
          binaryField(
            'Blob data · Base64URL',
            'blob',
            blob['write']?.toString() ?? '',
            (v) => update('largeBlob', {'write': v}),
          ),
        const Divider(height: 28),
        toggle(
          'Pseudo-random function (PRF)',
          ext.containsKey('prf'),
          (v) => update('prf', v ? <String, dynamic>{} : null),
        ),
        if (ext.containsKey('prf')) ...[
          binaryField(
            'PRF first · Base64URL',
            'prf.first',
            eval['first']?.toString() ?? '',
            (v) => prfValue('first', v),
          ),
          binaryField(
            'PRF second · Base64URL',
            'prf.second',
            eval['second']?.toString() ?? '',
            (v) => prfValue('second', v),
            enabled: eval.containsKey('first'),
          ),
          if (!widget.create)
            ExpansionTile(
              tilePadding: EdgeInsets.zero,
              title: const Text(
                'Per-credential PRF inputs',
                style: TextStyle(fontSize: 15),
              ),
              children: [
                for (final id in {
                  ...widget.credentialIds,
                  ...byCredential.keys.cast<String>(),
                }) ...[
                  Align(
                    alignment: Alignment.centerLeft,
                    child: Text(
                      id,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: const TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 13,
                      ),
                    ),
                  ),
                  binaryField(
                    'First · Base64URL',
                    '$id.first',
                    byCredential[id] is Map
                        ? byCredential[id]['first']?.toString() ?? ''
                        : '',
                    (v) => prfValue('first', v, credential: id),
                  ),
                  binaryField(
                    'Second · Base64URL',
                    '$id.second',
                    byCredential[id] is Map
                        ? byCredential[id]['second']?.toString() ?? ''
                        : '',
                    (v) => prfValue('second', v, credential: id),
                    enabled:
                        byCredential[id] is Map &&
                        (byCredential[id] as Map).containsKey('first'),
                  ),
                ],
                if (widget.credentialIds.isEmpty && byCredential.isEmpty)
                  const Padding(
                    padding: EdgeInsets.all(12),
                    child: Text(
                      'No allowed credentials',
                      style: TextStyle(fontSize: 14),
                    ),
                  ),
              ],
            ),
        ],
      ],
    );
  }
}
