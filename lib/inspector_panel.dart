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
        const SizedBox(height: 16),
        if (needsCose)
          ExpansionTile(
            childrenPadding: const EdgeInsets.fromLTRB(16, 12, 16, 16),
            title: const Text('SM2 decoding profile'),
            children: [
              TextField(
                controller: sm2Algorithm,
                onChanged: (_) => changed(),
                decoration: const InputDecoration(
                  labelText: 'SM2 algorithm ID',
                ),
              ),
              const SizedBox(height: 16),
              TextField(
                controller: sm2Curve,
                onChanged: (_) => changed(),
                decoration: const InputDecoration(labelText: 'SM2 curve ID'),
              ),
            ],
          ),
        const SizedBox(height: 16),
        Wrap(
          spacing: 8,
          runSpacing: 8,
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

/// Bounded, wrapping text avoids editable-text layout failures inside expansion
/// tiles. Short scalar values remain visible without another disclosure level.
class DecodedDataView extends StatelessWidget {
  final Object? value;
  final String path;
  const DecodedDataView({
    super.key,
    required this.value,
    this.path = 'decoded',
  });

  @override
  Widget build(BuildContext context) {
    final entries = value is Map
        ? (value as Map).entries.toList()
        : value is List
        ? (value as List).asMap().entries.toList()
        : null;
    if (entries == null) return _DecodedValue(value: value);
    return SizedBox(
      width: double.infinity,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          for (final entry in entries)
            if (entry.value is! Map &&
                entry.value is! List &&
                '${entry.value}'.length <= 80)
              Padding(
                padding: const EdgeInsets.symmetric(
                  horizontal: 16,
                  vertical: 12,
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Text(
                      '${entry.key}',
                      style: const TextStyle(fontWeight: FontWeight.w600),
                    ),
                    const SizedBox(height: 6),
                    _DecodedValue(value: entry.value),
                  ],
                ),
              )
            else
              ExpansionTile(
                key: PageStorageKey('$path/${entry.key}'),
                initiallyExpanded: entry.key == 'decodeErrors',
                title: Text(
                  '${entry.key}',
                  style: entry.key == 'decodeErrors'
                      ? TextStyle(color: Theme.of(context).colorScheme.error)
                      : null,
                ),
                subtitle: Text(
                  entry.value is Map
                      ? '${(entry.value as Map).length} fields'
                      : entry.value is List
                      ? '${(entry.value as List).length} items'
                      : "${'${entry.value}'.length} characters",
                ),
                childrenPadding: const EdgeInsets.fromLTRB(12, 0, 12, 12),
                expandedCrossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  DecodedDataView(
                    value: entry.value,
                    path: '$path/${entry.key}',
                  ),
                ],
              ),
        ],
      ),
    );
  }
}

class _DecodedValue extends StatelessWidget {
  final Object? value;
  const _DecodedValue({required this.value});

  @override
  Widget build(BuildContext context) {
    final text = value is String ? value as String : pretty(value);
    return SizedBox(
      width: double.infinity,
      child: SelectionArea(
        child: Text(
          text,
          softWrap: true,
          style: const TextStyle(
            fontFamily: 'monospace',
            fontSize: 14,
            height: 1.5,
          ),
        ),
      ),
    );
  }
}
