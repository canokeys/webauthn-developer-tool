import 'dart:convert';
import 'package:cbor/cbor.dart';
import 'package:fido2/fido2_server.dart';

String b64(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');
List<int> unb64(String text) => base64Url.decode(base64Url.normalize(text));
String pretty(Object? value) =>
    const JsonEncoder.withIndent('  ').convert(value);

Object? canonicalJson(Object? value) {
  if (value is Map) {
    final keys = value.keys.cast<String>().toList()..sort();
    return {for (final k in keys) k: canonicalJson(value[k])};
  }
  if (value is List) return value.map(canonicalJson).toList();
  return value;
}

Object? jsonValue(Object? value, {String format = 'b64u'}) {
  if (value is CborBytes) return binary(value.bytes, format);
  if (value is CborList) {
    return value.map((e) => jsonValue(e, format: format)).toList();
  }
  if (value is CborMap) {
    return {
      for (final e in value.entries)
        e.key.toObject().toString(): jsonValue(e.value, format: format),
    };
  }
  if (value is CborValue) return jsonValue(value.toObject(), format: format);
  if (value is Map) {
    return value.map(
      (k, v) => MapEntry(k.toString(), jsonValue(v, format: format)),
    );
  }
  if (value is List) {
    return value.map((e) => jsonValue(e, format: format)).toList();
  }
  return value;
}

String binary(List<int> bytes, String format) => switch (format) {
  'hex' => bytes.map((e) => e.toRadixString(16).padLeft(2, '0')).join(),
  'b64' => base64.encode(bytes),
  _ => b64(bytes),
};

List<int> decodeBinary(String input, String format) {
  final text = input.replaceAll(RegExp(r'\s'), '');
  if (format == 'hex') {
    final hex = text.replaceAll(':', '');
    if (hex.length.isOdd || !RegExp(r'^[0-9a-fA-F]*$').hasMatch(hex)) {
      throw const FormatException('Invalid hex');
    }
    return [
      for (var i = 0; i < hex.length; i += 2)
        int.parse(hex.substring(i, i + 2), radix: 16),
    ];
  }
  return base64.decode(base64.normalize(text));
}

Map<String, dynamic> inspectAuth(
  List<int> bytes,
  CoseConfiguration config,
  String format,
) {
  final data = AuthenticatorData.parse(bytes, configuration: config);
  return {
    'byteLength': bytes.length,
    'rpIdHash': binary(data.rpIdHash, format),
    'flags': {
      'value': data.flags,
      'UP': data.userPresent,
      'UV': data.userVerified,
      'BE': data.backupEligible,
      'BS': data.backedUp,
      'AT': data.hasAttestedCredentialData,
      'ED': data.hasExtensions,
    },
    'signCount': data.signCount,
    if (data.aaguid != null) 'aaguid': binary(data.aaguid!, 'hex'),
    if (data.credentialId != null)
      'credentialId': binary(data.credentialId!, format),
    if (data.attestedCredentialData != null)
      'credentialPublicKey': jsonValue(
        data.attestedCredentialData!.credentialPublicKey,
        format: format,
      ),
    if (data.extensions != null)
      'extensions': jsonValue(data.extensions, format: format),
  };
}

/// Accept raw browser responses, copied inspector envelopes and request reports.
Map<String, dynamic> credentialFromJson(Object? input) {
  if (input is! Map<String, dynamic>) {
    throw const FormatException('Expected a credential JSON object');
  }
  final value =
      input['credential'] ??
      (input.containsKey('operation') ? input['response'] : input);
  if (value is! Map<String, dynamic> || value['response'] is! Map) {
    throw const FormatException('Missing credential response');
  }
  return value;
}

Object? inspect(
  String input,
  String type,
  String inputFormat,
  String outputFormat,
  CoseConfiguration config,
) {
  if (input.trim().isEmpty) throw const FormatException('No input');
  if (input.length > 1000000) throw const FormatException('Input exceeds 1 MB');
  if (type == 'Credential JSON') {
    final value = credentialFromJson(jsonDecode(input));
    final response = value['response'];
    if (response is! Map) {
      throw const FormatException('Missing credential response');
    }
    final result = <String, dynamic>{
      'credentialInfo': {
        for (final key in ['id', 'rawId', 'type', 'authenticatorAttachment'])
          if (value.containsKey(key)) key: value[key],
        if (response['transports'] != null)
          'transports': response['transports'],
      },
    };
    final errors = <String, String>{};
    void field(String name, Object? Function() decode) {
      try {
        result[name] = decode();
      } catch (e) {
        errors[name] = '$e';
      }
    }

    field(
      'clientExtensionResults',
      () => inspectClientExtensions(
        value['clientExtensionResults'] as Map? ?? {},
        outputFormat,
      ),
    );
    field(
      'clientDataJSON',
      () =>
          jsonDecode(utf8.decode(unb64(response['clientDataJSON'] as String))),
    );
    if (response['attestationObject'] != null) {
      field(
        'attestationObject',
        () => inspect(
          response['attestationObject'],
          'Attestation object',
          'b64u',
          outputFormat,
          config,
        ),
      );
    }
    if (response['authenticatorData'] != null) {
      field(
        'authenticatorData',
        () => inspectAuth(
          unb64(response['authenticatorData']),
          config,
          outputFormat,
        ),
      );
      field(
        'signature',
        () => binary(unb64(response['signature']), outputFormat),
      );
      field('signatureBytes', () => unb64(response['signature']).length);
    }
    if (errors.isNotEmpty) result['decodeErrors'] = errors;
    return result;
  }
  if (type == 'JSON') return jsonDecode(input);
  final bytes = decodeBinary(input, inputFormat);
  if (type == 'Client data') return jsonDecode(utf8.decode(bytes));
  if (type == 'Authenticator data') {
    return inspectAuth(bytes, config, outputFormat);
  }
  if (type == 'COSE key') {
    return jsonValue(
      CoseKey.fromCbor(bytes, configuration: config).toCborMap(),
      format: outputFormat,
    );
  }
  final value = cbor.decode(bytes);
  if (type == 'Attestation object') {
    final map = value as CborMap;
    return {
      'fmt': map[CborString('fmt')]?.toObject(),
      'attStmt': jsonValue(map[CborString('attStmt')], format: outputFormat),
      'authData': inspectAuth(
        (map[CborString('authData')] as CborBytes).bytes,
        config,
        outputFormat,
      ),
    };
  }
  return jsonValue(value, format: outputFormat);
}

Map<String, dynamic> inspectClientExtensions(Map extensions, String format) {
  final result = jsonDecode(jsonEncode(extensions)) as Map<String, dynamic>;
  Object bytes(Object? value) {
    if (value is! String) return value ?? '';
    final decoded = unb64(value);
    return {'byteLength': decoded.length, 'value': binary(decoded, format)};
  }

  final prf = result['prf'];
  if (prf is Map && prf['results'] is Map) {
    final values = prf['results'] as Map;
    for (final key in ['first', 'second']) {
      if (values.containsKey(key)) values[key] = bytes(values[key]);
    }
  }
  final blob = result['largeBlob'];
  if (blob is Map && blob['blob'] != null) blob['blob'] = bytes(blob['blob']);
  return result;
}

List<int> responseAuthenticatorData(Map<String, dynamic> credential) {
  final response = credential['response'] as Map;
  if (response.containsKey('authenticatorData')) {
    return unb64(response['authenticatorData']);
  }
  final attestation =
      cbor.decode(unb64(response['attestationObject'])) as CborMap;
  return (attestation[CborString('authData')] as CborBytes).bytes;
}

class SavedCredential {
  final String rpId;
  final String username;
  final String created;
  final RegisteredCredential credential;
  final Sm2Configuration? sm2;
  final List<String> transports;
  SavedCredential({
    required this.rpId,
    required this.username,
    required this.created,
    required this.credential,
    this.sm2,
    List<String> transports = const [],
  }) : transports = List.unmodifiable(transports);
  Map<String, dynamic> toJson() => {
    'rpId': rpId,
    'username': username,
    'created': created,
    'id': b64(credential.id),
    'transports': transports,
    'key': b64(cbor.encode(credential.publicKey.toCborMap())),
    'signCount': credential.signCount,
    'backupEligible': credential.backupEligible,
    'backedUp': credential.backedUp,
    'userHandle': credential.userHandle == null
        ? null
        : b64(credential.userHandle!),
    if (sm2 != null)
      'sm2': {
        'algorithm': sm2!.algorithm,
        'curve': sm2!.curve,
        'id': sm2!.id,
        'encoding': sm2!.signatureEncoding.name,
      },
  };
  factory SavedCredential.fromJson(Map<String, dynamic> json) {
    final profile = json['sm2'] as Map<String, dynamic>?;
    final sm2 = profile == null
        ? null
        : Sm2Configuration(
            algorithm: profile['algorithm'],
            curve: profile['curve'],
            id: profile['id'],
            signatureEncoding: SignatureEncoding.values.byName(
              profile['encoding'],
            ),
            allowUnassignedIdentifiers: true,
          );
    return SavedCredential(
      rpId: json['rpId'],
      username: json['username'],
      created: json['created'],
      sm2: sm2,
      transports: (json['transports'] as List? ?? []).cast<String>(),
      credential: RegisteredCredential(
        id: unb64(json['id']),
        publicKey: CoseKey.fromCbor(
          unb64(json['key']),
          configuration: CoseConfiguration(sm2: sm2),
        ),
        signCount: json['signCount'],
        backupEligible: json['backupEligible'],
        backedUp: json['backedUp'],
        userHandle: json['userHandle'] == null
            ? null
            : unb64(json['userHandle']),
      ),
    );
  }
}
