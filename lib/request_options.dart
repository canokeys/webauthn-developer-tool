import 'dart:convert';

const credentialProtectionPolicies = [
  'userVerificationOptional',
  'userVerificationOptionalWithCredentialIDList',
  'userVerificationRequired',
];

void _binary(Object? value, String name) {
  if (value is! String || !RegExp(r'^[A-Za-z0-9_-]*={0,2}$').hasMatch(value)) {
    throw FormatException('$name must be Base64URL');
  }
  base64Url.decode(base64Url.normalize(value));
}

/// Validate only the extension contracts this workbench exposes. Unknown JSON
/// extensions are retained for the browser, never advertised as verified.
void validateRequestExtensions(String operation, Map<String, dynamic> options) {
  final extensions = options['extensions'];
  if (extensions == null) return;
  if (extensions is! Map) {
    throw const FormatException('Extensions must be a JSON object');
  }
  final create = operation == 'create';
  for (final name in [
    'credProps',
    'minPinLength',
    'enforceCredentialProtectionPolicy',
  ]) {
    if (extensions.containsKey(name) && extensions[name] is! bool) {
      throw FormatException('$name must be a boolean');
    }
    if (!create && extensions.containsKey(name)) {
      throw FormatException('$name is a registration extension');
    }
  }
  final policy = extensions['credentialProtectionPolicy'];
  if (policy != null &&
      (!create || !credentialProtectionPolicies.contains(policy))) {
    throw const FormatException('Invalid credential protection policy');
  }
  if (extensions['enforceCredentialProtectionPolicy'] == true &&
      policy == null) {
    throw const FormatException(
      'Select a credential protection policy before enforcing it',
    );
  }
  final blob = extensions['largeBlob'];
  if (blob != null) {
    if (blob is! Map) {
      throw const FormatException('largeBlob must be an object');
    }
    if (create) {
      if (!['preferred', 'required'].contains(blob['support']) ||
          blob.containsKey('read') ||
          blob.containsKey('write')) {
        throw const FormatException(
          'Registration largeBlob requires support: preferred or required',
        );
      }
    } else {
      if (blob.containsKey('support') ||
          (blob['read'] == true) == blob.containsKey('write')) {
        throw const FormatException('Choose either largeBlob read or write');
      }
      if (blob.containsKey('read') && blob['read'] is! bool) {
        throw const FormatException('largeBlob.read must be a boolean');
      }
      if (blob.containsKey('write')) {
        _binary(blob['write'], 'largeBlob.write');
        final allowed = options['allowCredentials'];
        if (allowed is! List || allowed.length != 1) {
          throw const FormatException(
            'Writing a largeBlob requires exactly one allowed credential',
          );
        }
      }
    }
  }
  final prf = extensions['prf'];
  if (prf != null) {
    if (prf is! Map) throw const FormatException('prf must be an object');
    void evaluation(Object? input, String name) {
      if (input is! Map || !input.containsKey('first')) {
        throw FormatException('$name requires first');
      }
      _binary(input['first'], '$name.first');
      if (input.containsKey('second')) _binary(input['second'], '$name.second');
    }

    if (prf.containsKey('eval')) evaluation(prf['eval'], 'prf.eval');
    if (prf.containsKey('evalByCredential')) {
      if (create) {
        throw const FormatException(
          'prf.evalByCredential is an authentication extension',
        );
      }
      final values = prf['evalByCredential'];
      if (values is! Map) {
        throw const FormatException('prf.evalByCredential must be an object');
      }
      final allowed = options['allowCredentials'] as List? ?? [];
      for (final entry in values.entries) {
        _binary(entry.key, 'PRF credential ID');
        if (entry.key.toString().isEmpty ||
            !allowed.any((c) => c is Map && c['id'] == entry.key)) {
          throw const FormatException(
            'Each PRF credential ID must be present in allowCredentials',
          );
        }
        evaluation(entry.value, 'prf.evalByCredential.${entry.key}');
      }
    }
  }
}
