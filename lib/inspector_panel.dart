import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:fido2/fido2_server.dart';
import 'protocol.dart';

/// A manual decoding workspace independent of ceremony and request state.
class InspectorPanel extends StatefulWidget {
  const InspectorPanel({super.key});

  @override
  State<InspectorPanel> createState() => _InspectorPanelState();
}

class _InspectorPanelState extends State<InspectorPanel> {
  final input = TextEditingController();
  final sm2Algorithm = TextEditingController(text: '-54');
  final sm2Curve = TextEditingController(text: '9');
  String type = 'Credential JSON', encoding = 'b64u', output = 'hex';
  Object? result;
  String? error;
  bool stale = false;
  String? snapshot;
  String? snapshotType, snapshotEncoding;
  CoseConfiguration? snapshotConfig;

  bool get jsonInput => type == 'Credential JSON' || type == 'JSON';
  bool get needsCose => !['JSON', 'Client data', 'CBOR'].contains(type);

  @override
  void dispose() {
    input.dispose();
    sm2Algorithm.dispose();
    sm2Curve.dispose();
    super.dispose();
  }

  void changed() => setState(() => stale = snapshot != null);

  void decode({bool presentationOnly = false}) {
    setState(() {
      try {
        if (!presentationOnly) {
          snapshot = input.text;
          snapshotType = type;
          snapshotEncoding = encoding;
          snapshotConfig = null;
          stale = false;
          snapshotConfig = CoseConfiguration(
            sm2: !needsCose
                ? null
                : Sm2Configuration(
                    algorithm: int.parse(sm2Algorithm.text),
                    curve: int.parse(sm2Curve.text),
                    allowUnassignedIdentifiers: true,
                  ),
          );
          stale = false;
        }
        result = inspect(
          snapshot!,
          snapshotType!,
          snapshotEncoding!,
          output,
          snapshotConfig!,
        );
        error = null;
      } catch (e) {
        result = null;
        error = '$e';
      }
    });
  }

  Widget select(
    String label,
    String value,
    List<String> options,
    void Function(String) update,
  ) => DropdownButtonFormField<String>(
    key: ValueKey('$label/$value'),
    initialValue: value,
    decoration: InputDecoration(labelText: label),
    items: [
      for (final item in options)
        DropdownMenuItem(value: item, child: Text(item)),
    ],
    onChanged: (value) {
      update(value!);
      changed();
    },
  );

  @override
  Widget build(BuildContext context) => SingleChildScrollView(
    padding: const EdgeInsets.all(24),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text('Manual inspector', style: Theme.of(context).textTheme.titleLarge),
        const SizedBox(height: 8),
        const Text(
          'Decode pasted data. This workspace does not verify signatures or change request settings.',
        ),
        const SizedBox(height: 20),
        select('Input type', type, [
          'Credential JSON',
          'Attestation object',
          'Authenticator data',
          'COSE key',
          'Client data',
          'CBOR',
          'JSON',
        ], (v) => type = v),
        if (!jsonInput) ...[
          const SizedBox(height: 12),
          select('Input encoding', encoding, [
            'b64u',
            'b64',
            'hex',
          ], (v) => encoding = v),
        ],
        const SizedBox(height: 16),
        TextField(
          controller: input,
          style: const TextStyle(fontFamily: 'monospace', fontSize: 14),
          minLines: 4,
          maxLines: 8,
          onChanged: (_) => changed(),
          decoration: InputDecoration(
            hintText: jsonInput
                ? 'Paste a raw credential, exported report, or JSON object'
                : 'Paste encoded bytes',
          ),
        ),
        if (needsCose)
          ExpansionTile(
            title: const Text('SM2 decoding profile'),
            children: [
              TextField(
                controller: sm2Algorithm,
                onChanged: (_) => changed(),
                decoration: const InputDecoration(
                  labelText: 'SM2 algorithm ID',
                ),
              ),
              TextField(
                controller: sm2Curve,
                onChanged: (_) => changed(),
                decoration: const InputDecoration(labelText: 'SM2 curve ID'),
              ),
            ],
          ),
        Wrap(
          spacing: 8,
          children: [
            FilledButton(
              onPressed: () => decode(),
              child: const Text('Decode'),
            ),
            TextButton(
              onPressed: () => setState(() {
                input.clear();
                result = null;
                error = null;
                snapshot = null;
                stale = false;
              }),
              child: const Text('Clear'),
            ),
          ],
        ),
        const SizedBox(height: 24),
        Wrap(
          spacing: 8,
          crossAxisAlignment: WrapCrossAlignment.center,
          children: [
            const Text('Binary output'),
            for (final format in ['hex', 'b64', 'b64u'])
              ChoiceChip(
                label: Text(format),
                selected: output == format,
                onSelected: (_) {
                  setState(() => output = format);
                  if (snapshot != null && snapshotConfig != null) {
                    decode(presentationOnly: true);
                  }
                },
              ),
          ],
        ),
        if (stale)
          const Padding(
            padding: EdgeInsets.symmetric(vertical: 12),
            child: Text('Input changed. Decode again to update the result.'),
          ),
        if (error != null)
          SelectableText(
            error!,
            style: TextStyle(color: Theme.of(context).colorScheme.error),
          ),
        if (result != null) ...[
          TextButton.icon(
            onPressed: stale
                ? null
                : () => Clipboard.setData(
                    ClipboardData(
                      text: pretty(
                        snapshotType == 'Credential JSON'
                            ? {
                                'credential': _rawCredential(),
                                'decoded': result,
                              }
                            : result,
                      ),
                    ),
                  ),
            icon: const Icon(Icons.copy),
            label: Text(
              snapshotType == 'Credential JSON'
                  ? 'Copy credential and decoded data'
                  : 'Copy decoded data',
            ),
          ),
          DecodedDataView(value: result),
        ],
      ],
    ),
  );

  Object? _rawCredential() {
    if (snapshotType != 'Credential JSON') return null;
    return credentialFromJson(jsonDecode(snapshot!));
  }
}

/// Collapsible fields keep large certificate and public-key data out of the way.
class DecodedDataView extends StatelessWidget {
  final Object? value;
  const DecodedDataView({super.key, required this.value});

  @override
  Widget build(BuildContext context) {
    final entries = value is Map ? (value as Map).entries.toList() : null;
    if (entries == null) return SelectableText(pretty(value));
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        for (final entry in entries)
          ExpansionTile(
            key: PageStorageKey('decoded-${entry.key}'),
            initiallyExpanded: entry.key == 'decodeErrors',
            title: Text(
              '${entry.key}',
              style: entry.key == 'decodeErrors'
                  ? TextStyle(color: Theme.of(context).colorScheme.error)
                  : null,
            ),
            subtitle: entry.value is Map || entry.value is List
                ? null
                : Text(
                    '${entry.value}',
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
            childrenPadding: const EdgeInsets.all(12),
            expandedCrossAxisAlignment: CrossAxisAlignment.start,
            children: [
              entry.value is Map
                  ? DecodedDataView(value: entry.value)
                  : SelectableText(pretty(entry.value)),
            ],
          ),
      ],
    );
  }
}
