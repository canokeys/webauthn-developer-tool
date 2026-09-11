import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:fido2/fido2_server.dart';
import 'browser.dart' as browser;
import 'protocol.dart';
import 'inspector_panel.dart';
import 'extensions_editor.dart';
import 'request_options.dart';
import 'passkey_autofill.dart';

const green = Color(0xff147d64);
const ink = Color(0xff202b29);
const muted = Color(0xff677673);
const line = Color(0xffdde5e2);
const mono = TextStyle(
  fontFamily: 'monospace',
  fontSize: 14,
  height: 1.65,
  letterSpacing: 0,
);

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  // Keep Flutter controls accessible to assistive technology and browser tests.
  WidgetsBinding.instance.ensureSemantics();
  runApp(const WorkbenchApp());
}

class WorkbenchApp extends StatelessWidget {
  const WorkbenchApp({super.key});
  @override
  Widget build(BuildContext context) => MaterialApp(
    debugShowCheckedModeBanner: false,
    title: 'CanoKey | WebAuthn Workbench',
    theme: ThemeData(
      useMaterial3: true,
      scaffoldBackgroundColor: const Color(0xfff6f8f8),
      colorScheme: ColorScheme.fromSeed(
        seedColor: green,
        primary: green,
        surface: Colors.white,
        onSurface: ink,
      ),
      textTheme: const TextTheme(
        bodyMedium: TextStyle(fontSize: 16, letterSpacing: 0),
        bodySmall: TextStyle(fontSize: 14, color: muted, letterSpacing: 0),
      ),
      inputDecorationTheme: InputDecorationTheme(
        isDense: true,
        filled: true,
        fillColor: Colors.white,
        labelStyle: const TextStyle(color: muted, fontSize: 15),
        contentPadding: const EdgeInsets.symmetric(
          horizontal: 12,
          vertical: 15,
        ),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(5),
          borderSide: const BorderSide(color: line),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(5),
          borderSide: const BorderSide(color: line),
        ),
      ),
      dividerColor: line,
      filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(
          minimumSize: const Size(0, 44),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(5)),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(5)),
          side: const BorderSide(color: line),
        ),
      ),
    ),
    home: const Workbench(),
  );
}

class Workbench extends StatefulWidget {
  const Workbench({super.key});
  @override
  State<Workbench> createState() => _WorkbenchState();
}

class _WorkbenchState extends State<Workbench> {
  final rp = TextEditingController();
  final rpName = TextEditingController(text: 'CanoKey Workbench');
  final username = TextEditingController(text: 'alice@example.com');
  final displayName = TextEditingController(text: 'Alice');
  final userId = TextEditingController();
  final challenge = TextEditingController();
  final timeout = TextEditingController(text: '60000');
  final sm2Alg = TextEditingController(text: '-54');
  final sm2Curve = TextEditingController(text: '9');
  final createExtensions = TextEditingController(text: '{}');
  final assertionExtensions = TextEditingController(text: '{}');
  TextEditingController get extensions =>
      mode == 'create' ? createExtensions : assertionExtensions;
  final hintSelections = <String, List<String>>{'create': [], 'get': []};
  List<String> get hints => hintSelections[mode]!;
  String mediation = 'optional';
  final requestJson = TextEditingController();
  final algorithms = <String>['ES256'];
  final history = <Map<String, dynamic>>[];
  List<SavedCredential> credentials = [];
  late final Map<String, dynamic> env;
  String mode = 'create', leftTab = 'Form', rightTab = 'Result';
  String uv = 'preferred',
      rk = 'discouraged',
      attachment = 'any',
      attestation = 'direct';
  String outputFormat = 'hex';
  String workspace = 'Workbench';
  String? selectedId;
  String status = '';
  String get rawResponse =>
      lastReport?['response'] == null ? '' : pretty(lastReport!['response']);
  bool ready = false,
      busy = false,
      statusError = false,
      excludeExisting = false;
  Map<String, dynamic>? lastReport;

  @override
  void initState() {
    super.initState();
    env = jsonDecode(browser.environment());
    rp.text = env['hostname'];
    for (final c in [
      rp,
      rpName,
      username,
      displayName,
      userId,
      challenge,
      timeout,
      sm2Alg,
      sm2Curve,
      createExtensions,
      assertionExtensions,
    ]) {
      c.addListener(_formChanged);
    }
    _initialize();
  }

  @override
  void dispose() {
    for (final c in [
      rp,
      rpName,
      username,
      displayName,
      userId,
      challenge,
      timeout,
      sm2Alg,
      sm2Curve,
      createExtensions,
      assertionExtensions,
      requestJson,
    ]) {
      c.dispose();
    }
    super.dispose();
  }

  Future<void> _initialize() async {
    try {
      await RustCrypto.initialize(wasmModuleUrl: 'crypto/web/fido2_crypto.js');
      userId.text = b64(RustCrypto.randomBytes(24));
      challenge.text = b64(RustCrypto.randomBytes(32));
      try {
        credentials = (jsonDecode(browser.readCredentials()) as List)
            .map((e) => SavedCredential.fromJson(Map<String, dynamic>.from(e)))
            .toList();
      } catch (e) {
        status = 'Stored credentials could not be loaded: $e';
        statusError = true;
      }
      if (!mounted) return;
      setState(() {
        ready = true;
      });
      _syncRequest();
    } catch (e) {
      if (mounted) {
        setState(() {
          status = '$e';
          statusError = true;
        });
      }
    }
  }

  void _formChanged() {
    if (!mounted) return;
    if (leftTab == 'Form') _syncRequest();
    setState(() {});
  }

  Sm2Configuration get sm2 => Sm2Configuration(
    algorithm: int.parse(sm2Alg.text),
    curve: int.parse(sm2Curve.text),
    id: '1234567812345678',
    signatureEncoding: SignatureEncoding.raw,
    allowUnassignedIdentifiers: true,
  );
  CoseConfiguration get cose =>
      CoseConfiguration(sm2: algorithms.contains('SM2') ? sm2 : null);
  int algorithmId(String label) => switch (label) {
    'ES256' => -7,
    'Ed25519' => -8,
    'ML-DSA-44' => -48,
    'ML-DSA-65' => -49,
    'ML-DSA-87' => -50,
    _ => int.parse(sm2Alg.text),
  };
  String algorithmName(int id) => switch (id) {
    -7 => 'ES256',
    -8 => 'Ed25519',
    -48 => 'ML-DSA-44',
    -49 => 'ML-DSA-65',
    -50 => 'ML-DSA-87',
    _ => 'SM2 ($id)',
  };
  List<SavedCredential> get matching =>
      credentials.where((c) => c.rpId == rp.text).toList();

  Map<String, dynamic> _descriptor(SavedCredential c) => {
    'type': 'public-key',
    'id': b64(c.credential.id),
    if (c.transports.isNotEmpty) 'transports': c.transports,
  };

  Map<String, dynamic> _options() {
    final ext = jsonDecode(extensions.text);
    if (ext is! Map<String, dynamic>) {
      throw const FormatException('Extensions must be a JSON object');
    }
    final ms = int.parse(timeout.text);
    if (ms < 1 || ms > 600000) {
      throw const FormatException('Timeout must be 1 to 600000 ms');
    }
    final ids = matching
        .where((c) => selectedId == null || b64(c.credential.id) == selectedId)
        .map(_descriptor)
        .toList();
    return {
      'challenge': challenge.text,
      'timeout': ms,
      if (hints.isNotEmpty) 'hints': hints.toList(),
      if (mode == 'create') ...{
        'rp': {'id': rp.text, 'name': rpName.text},
        'user': {
          'id': userId.text,
          'name': username.text,
          'displayName': displayName.text,
        },
        'pubKeyCredParams': algorithms
            .map((a) => {'type': 'public-key', 'alg': algorithmId(a)})
            .toList(),
        'authenticatorSelection': {
          'residentKey': rk,
          'requireResidentKey': rk == 'required',
          'userVerification': uv,
          if (attachment != 'any') 'authenticatorAttachment': attachment,
        },
        'attestation': attestation,
        'excludeCredentials': excludeExisting
            ? matching.map(_descriptor).toList()
            : [],
      } else ...{
        'rpId': rp.text,
        'userVerification': uv,
        'allowCredentials': selectedId == '*' ? [] : ids,
      },
      'extensions': ext,
    };
  }

  void _syncRequest() {
    try {
      requestJson.text = pretty(_options());
    } catch (_) {
      /* Keep the last valid preview while a field is being edited. */
    }
  }

  void _changed(VoidCallback update) {
    setState(update);
    if (leftTab == 'Form') _syncRequest();
  }

  void _switchMode(String value) {
    if (busy || value == mode) return;
    _changed(() {
      mode = value;
      leftTab = 'Form';
      status = '';
      if (ready) challenge.text = b64(RustCrypto.randomBytes(32));
    });
  }

  void _resetRequest() {
    _changed(() {
      leftTab = 'Form';
      rp.text = env['hostname'];
      rpName.text = 'CanoKey Workbench';
      username.text = 'alice@example.com';
      displayName.text = 'Alice';
      userId.text = b64(RustCrypto.randomBytes(24));
      challenge.text = b64(RustCrypto.randomBytes(32));
      timeout.text = '60000';
      algorithms
        ..clear()
        ..add('ES256');
      hints.clear();
      uv = 'preferred';
      rk = 'discouraged';
      attachment = 'any';
      attestation = 'direct';
      selectedId = null;
      mediation = 'optional';
      excludeExisting = false;
      extensions.text = '{}';
      status = '';
    });
  }

  Future<void> _switchEditor(String value) async {
    if (value == leftTab) return;
    if (value == 'Form') {
      final controllers = [
        rp,
        rpName,
        username,
        displayName,
        userId,
        challenge,
        timeout,
        extensions,
      ];
      final oldText = controllers.map((c) => c.text).toList();
      final oldAlgorithms = algorithms.toList();
      final oldHints = hints.toList();
      final oldSelection = (
        rk,
        uv,
        attachment,
        attestation,
        selectedId,
        excludeExisting,
      );
      try {
        final o = jsonDecode(requestJson.text) as Map<String, dynamic>;
        // Apply all form-representable fields. JSON-only fields stay in JSON mode.
        final supported = mode == 'create'
            ? {
                'rp',
                'user',
                'challenge',
                'timeout',
                'pubKeyCredParams',
                'authenticatorSelection',
                'attestation',
                'excludeCredentials',
                'extensions',
                'hints',
              }
            : {
                'rpId',
                'challenge',
                'timeout',
                'userVerification',
                'allowCredentials',
                'extensions',
                'hints',
              };
        if (o.keys.any((k) => !supported.contains(k))) {
          throw const FormatException(
            'Request has JSON-only fields. Continue in JSON mode.',
          );
        }
        challenge.text = o['challenge'];
        timeout.text = '${o['timeout'] ?? 60000}';
        extensions.text = pretty(o['extensions'] ?? {});
        final parsedHints = (o['hints'] as List? ?? []).cast<String>();
        if (parsedHints.any(
          (v) => !['security-key', 'client-device', 'hybrid'].contains(v),
        )) {
          throw const FormatException('Custom hints require JSON mode');
        }
        hints
          ..clear()
          ..addAll(parsedHints);
        if (mode == 'create') {
          rp.text = o['rp']['id'];
          rpName.text = o['rp']['name'];
          userId.text = o['user']['id'];
          username.text = o['user']['name'];
          displayName.text = o['user']['displayName'];
          final labels = <String>[];
          for (final a in o['pubKeyCredParams'] as List) {
            final id = a['alg'] as int;
            final label = id == int.tryParse(sm2Alg.text)
                ? 'SM2'
                : algorithmName(id);
            if (![
              'ES256',
              'Ed25519',
              'SM2',
              'ML-DSA-44',
              'ML-DSA-65',
              'ML-DSA-87',
            ].contains(label)) {
              throw const FormatException(
                'Custom algorithm requires JSON mode',
              );
            }
            labels.add(label);
          }
          algorithms
            ..clear()
            ..addAll(labels);
          final s = o['authenticatorSelection'] as Map? ?? {};
          if (s.keys.any(
            (k) => ![
              'residentKey',
              'requireResidentKey',
              'userVerification',
              'authenticatorAttachment',
            ].contains(k),
          )) {
            throw const FormatException('Selection has JSON-only fields');
          }
          rk = s['residentKey'] ?? 'discouraged';
          uv = s['userVerification'] ?? 'preferred';
          attachment = s['authenticatorAttachment'] ?? 'any';
          attestation = o['attestation'] ?? 'none';
          final excluded = o['excludeCredentials'] ?? [];
          if (jsonEncode(excluded) !=
                  jsonEncode(matching.map(_descriptor).toList()) &&
              (excluded as List).isNotEmpty) {
            throw const FormatException('Custom exclusions require JSON mode');
          }
          excludeExisting = (excluded as List).isNotEmpty;
        } else {
          rp.text = o['rpId'];
          uv = o['userVerification'] ?? 'preferred';
          final allowed = o['allowCredentials'] as List? ?? [];
          if (allowed.isEmpty) {
            selectedId = '*';
          } else if (allowed.length == 1 &&
              matching.any(
                (c) => b64(c.credential.id) == allowed.first['id'],
              )) {
            selectedId = allowed.first['id'];
          } else if (jsonEncode(canonicalJson(allowed)) ==
              jsonEncode(canonicalJson(matching.map(_descriptor).toList()))) {
            selectedId = null;
          } else {
            throw const FormatException(
              'Custom credential list requires JSON mode',
            );
          }
        }
        if (!['preferred', 'required', 'discouraged'].contains(uv) ||
            !['preferred', 'required', 'discouraged'].contains(rk) ||
            !['any', 'platform', 'cross-platform'].contains(attachment) ||
            ![
              'none',
              'direct',
              'indirect',
              'enterprise',
            ].contains(attestation)) {
          throw const FormatException('Custom values require JSON mode');
        }
        final represented = _options();
        for (final entry in o.entries) {
          if (jsonEncode(canonicalJson(entry.value)) !=
              jsonEncode(canonicalJson(represented[entry.key]))) {
            throw FormatException(
              '${entry.key} contains JSON-only values. Continue in JSON mode.',
            );
          }
        }
      } catch (e) {
        for (var i = 0; i < controllers.length; i++) {
          controllers[i].text = oldText[i];
        }
        algorithms
          ..clear()
          ..addAll(oldAlgorithms);
        hints
          ..clear()
          ..addAll(oldHints);
        rk = oldSelection.$1;
        uv = oldSelection.$2;
        attachment = oldSelection.$3;
        attestation = oldSelection.$4;
        selectedId = oldSelection.$5;
        excludeExisting = oldSelection.$6;
        setState(() {});
        _notice('$e');
        return;
      }
    } else {
      _syncRequest();
    }
    setState(() => leftTab = value);
  }

  Future<void> _execute() async {
    if (!ready || busy) return;
    String responseText = '';
    Map<String, dynamic>? options;
    CoseConfiguration? reportCose;
    final operation = mode;
    final requestMediation = operation == 'get' ? mediation : 'optional';
    final watch = Stopwatch()..start();
    setState(() {
      busy = true;
      status = 'Waiting for authenticator';
      statusError = false;
      rightTab = 'Result';
      lastReport = null;
    });
    try {
      options = leftTab == 'JSON'
          ? jsonDecode(requestJson.text) as Map<String, dynamic>
          : _options();
      final snapshot = jsonDecode(jsonEncode(options)) as Map<String, dynamic>;
      validateRequestExtensions(operation, snapshot);
      if (requestMediation == 'conditional' &&
          (snapshot['allowCredentials'] as List? ?? []).isNotEmpty) {
        throw const FormatException(
          'Autofill requires discoverable credential selection',
        );
      }
      final expectedChallenge = unb64(snapshot['challenge']);
      if (expectedChallenge.length < 16) {
        throw const FormatException('Challenge must be at least 16 bytes');
      }
      final requestRp = operation == 'create'
          ? snapshot['rp']['id'] as String
          : snapshot['rpId'] as String;
      final offered = operation == 'create'
          ? (snapshot['pubKeyCredParams'] as List)
                .map((a) => a['alg'] as int)
                .toList()
          : credentials
                .where((c) => c.rpId == requestRp)
                .map((c) => c.credential.publicKey.algorithmId)
                .toSet()
                .toList();
      final requestCose = operation == 'create'
          ? CoseConfiguration(
              sm2: offered.contains(int.tryParse(sm2Alg.text)) ? sm2 : null,
            )
          : CoseConfiguration();
      reportCose = requestCose;
      // Configuration and challenge are captured before invoking the authenticator.
      final selection = snapshot['authenticatorSelection'] as Map?;
      final registrationUv = selection == null
          ? null
          : selection['userVerification'];
      final server = operation != 'create'
          ? null
          : Fido2Server(
              Fido2Config(
                rpId: requestRp,
                origins: {env['origin']},
                signatureAlgorithms: offered,
                cose: requestCose,
                requireUserVerification:
                    (operation == 'create'
                        ? registrationUv
                        : snapshot['userVerification']) ==
                    'required',
              ),
            );
      if (operation == 'create') {
        final handle = unb64(snapshot['user']['id']);
        if (handle.isEmpty || handle.length > 64) {
          throw const FormatException('User ID must be 1 to 64 bytes');
        }
      }
      responseText = await browser.perform(
        operation,
        jsonEncode(snapshot),
        mediation: requestMediation,
      );
      final response = jsonDecode(responseText) as Map<String, dynamic>;
      if (operation == 'create') {
        final record = server!.registerComplete(
          response,
          expectedChallenge: expectedChallenge,
          offeredAlgorithms: offered,
          userHandle: unb64(snapshot['user']['id']),
        );
        final saved = SavedCredential(
          rpId: requestRp,
          username: snapshot['user']['name'],
          created: DateTime.now().toIso8601String(),
          credential: record,
          sm2: record.publicKey is SM2 ? requestCose.sm2 : null,
          transports:
              ((response['response'] as Map)['transports'] as List? ?? [])
                  .cast<String>(),
        );
        credentials.removeWhere(
          (c) => c.rpId == requestRp && b64(c.credential.id) == b64(record.id),
        );
        credentials.add(saved);
        selectedId = b64(record.id);
        status =
            'Registration verified · ${algorithmName(record.publicKey.algorithmId)} · ${watch.elapsedMilliseconds} ms';
      } else {
        final id = response['rawId'];
        final index = credentials.indexWhere(
          (c) => c.rpId == requestRp && b64(c.credential.id) == id,
        );
        if (index < 0) {
          throw const FormatException(
            'No saved public key for this credential. Response captured; signature not verified.',
          );
        }
        final allowed = snapshot['allowCredentials'] as List? ?? [];
        if (allowed.isNotEmpty && !allowed.any((c) => c['id'] == id)) {
          throw const FormatException('Returned credential was not requested');
        }
        final saved = credentials[index];
        reportCose = CoseConfiguration(sm2: saved.sm2);
        final verificationServer = Fido2Server(
          Fido2Config(
            rpId: requestRp,
            origins: {env['origin']},
            signatureAlgorithms: [saved.credential.publicKey.algorithmId],
            cose: CoseConfiguration(sm2: saved.sm2),
            requireUserVerification: snapshot['userVerification'] == 'required',
          ),
        );
        final result = verificationServer.authenticateCompleteResult(
          response,
          credential: saved.credential,
          expectedChallenge: expectedChallenge,
          requireUserHandle: allowed.isEmpty,
        );
        credentials[index] = SavedCredential(
          rpId: saved.rpId,
          username: saved.username,
          created: saved.created,
          sm2: saved.sm2,
          transports: saved.transports,
          credential: RegisteredCredential(
            id: saved.credential.id,
            publicKey: saved.credential.publicKey,
            signCount: result.signCount,
            backupEligible: saved.credential.backupEligible,
            backedUp: result.backedUp,
            userHandle: saved.credential.userHandle,
          ),
        );
        status =
            'Signature verified · ${algorithmName(saved.credential.publicKey.algorithmId)} · ${watch.elapsedMilliseconds} ms';
      }
      try {
        browser.saveCredentials(
          jsonEncode(credentials.map((c) => c.toJson()).toList()),
        );
      } catch (e) {
        status += ' · Local save failed: $e';
      }
    } catch (e) {
      statusError = true;
      status = '$e';
    } finally {
      watch.stop();
      lastReport = {
        'time': DateTime.now().toIso8601String(),
        'operation': operation,
        'mediation': requestMediation,
        'verified': !statusError,
        'result': status,
        'durationMs': watch.elapsedMilliseconds,
        'request': options,
        if (reportCose?.sm2 != null)
          'inspectionProfile': {
            'algorithm': reportCose!.sm2!.algorithm,
            'curve': reportCose.sm2!.curve,
          },
        if (responseText.isNotEmpty) 'response': jsonDecode(responseText),
      };
      history.insert(0, lastReport!);
      if (history.length > 30) history.removeLast();
      // The next ceremony always starts with a new challenge, including JSON mode.
      final nonce = b64(RustCrypto.randomBytes(32));
      challenge.text = nonce;
      if (leftTab == 'JSON' && options != null) {
        requestJson.text = pretty({...options, 'challenge': nonce});
      }
      if (mounted) setState(() => busy = false);
    }
  }

  void _notice(String value, {SnackBarAction? action}) {
    ScaffoldMessenger.of(context)
      ..clearSnackBars()
      ..showSnackBar(
        SnackBar(
          content: Text(value),
          action: action,
          persist: false,
          duration: Duration(seconds: action == null ? 4 : 6),
          showCloseIcon: true,
        ),
      );
  }

  Future<void> _copy(String value) async {
    await Clipboard.setData(ClipboardData(text: value));
    if (mounted) _notice('Copied');
  }

  Widget _field(
    String label,
    TextEditingController c, {
    bool code = false,
    Widget? suffix,
    int lines = 1,
  }) => TextField(
    controller: c,
    enabled: !busy,
    maxLines: lines,
    style: code ? mono : const TextStyle(fontSize: 16),
    decoration: InputDecoration(labelText: label, suffixIcon: suffix),
  );
  Widget _select(
    String label,
    String value,
    List<String> options,
    ValueChanged<String> update,
  ) => DropdownButtonFormField<String>(
    key: ValueKey('$label/$value'),
    initialValue: options.contains(value) ? value : options.first,
    isExpanded: true,
    decoration: InputDecoration(labelText: label),
    style: const TextStyle(fontSize: 15, color: ink),
    items: options
        .map(
          (o) => DropdownMenuItem(
            value: o,
            child: Text(o, overflow: TextOverflow.ellipsis),
          ),
        )
        .toList(),
    onChanged: busy ? null : (v) => _changed(() => update(v!)),
  );
  Widget _pair(Widget a, Widget b) => Row(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Expanded(child: a),
      const SizedBox(width: 12),
      Expanded(child: b),
    ],
  );
  Widget _section(String number, String title, List<Widget> children) =>
      Padding(
        padding: const EdgeInsets.fromLTRB(22, 22, 22, 0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Text(
                  number,
                  style: const TextStyle(
                    fontSize: 13,
                    color: green,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(width: 10),
                Text(
                  title,
                  style: const TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 18),
            for (final c in children) ...[c, const SizedBox(height: 14)],
            const Divider(height: 8),
          ],
        ),
      );

  Widget _form() => Column(
    children: [
      _section('01', 'Relying party', [
        _field('RP ID', rp, code: true),
        if (mode == 'create') _field('RP name', rpName),
      ]),
      if (mode == 'create')
        _section('02', 'User identity', [
          _pair(
            _field('Username', username),
            _field('Display name', displayName),
          ),
          _field(
            'User ID · Base64URL',
            userId,
            code: true,
            suffix: IconButton(
              tooltip: 'Generate user ID',
              onPressed: ready && !busy
                  ? () => userId.text = b64(RustCrypto.randomBytes(24))
                  : null,
              icon: const Icon(Icons.refresh, size: 18),
            ),
          ),
        ]),
      if (mode == 'create')
        _section('03', 'Signature algorithms', [
          Wrap(
            spacing: 7,
            runSpacing: 7,
            children:
                [
                      'ES256',
                      'Ed25519',
                      'SM2',
                      'ML-DSA-44',
                      'ML-DSA-65',
                      'ML-DSA-87',
                    ]
                    .map(
                      (a) => FilterChip(
                        label: Text(a, style: const TextStyle(fontSize: 14)),
                        selected: algorithms.contains(a),
                        selectedColor: const Color(0xffdef0e9),
                        backgroundColor: Colors.white,
                        shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(4),
                          side: const BorderSide(color: line),
                        ),
                        onSelected: busy
                            ? null
                            : (v) => _changed(() {
                                if (v) {
                                  algorithms.add(a);
                                } else {
                                  algorithms.remove(a);
                                }
                              }),
                      ),
                    )
                    .toList(),
          ),
          if (algorithms.isNotEmpty) ...[
            for (var i = 0; i < algorithms.length; i++)
              SizedBox(
                height: 34,
                child: Row(
                  children: [
                    SizedBox(
                      width: 22,
                      child: Text(
                        '${i + 1}',
                        style: const TextStyle(fontSize: 13, color: muted),
                      ),
                    ),
                    Expanded(
                      child: Text(
                        algorithms[i],
                        style: const TextStyle(fontSize: 14),
                      ),
                    ),
                    Text(
                      '${algorithms[i] == 'SM2' ? sm2Alg.text : algorithmId(algorithms[i])}',
                      style: mono.copyWith(color: muted),
                    ),
                    IconButton(
                      tooltip: 'Move ${algorithms[i]} up',
                      visualDensity: VisualDensity.compact,
                      iconSize: 16,
                      onPressed: i > 0 && !busy
                          ? () => _changed(() {
                              final a = algorithms.removeAt(i);
                              algorithms.insert(i - 1, a);
                            })
                          : null,
                      icon: const Icon(Icons.arrow_upward),
                    ),
                  ],
                ),
              ),
          ],
          if (algorithms.contains('SM2')) ...[
            _pair(
              _field('SM2 algorithm ID', sm2Alg, code: true),
              _field('SM2 curve ID', sm2Curve, code: true),
            ),
          ],
        ]),
      if (mode == 'get')
        _section('02', 'Credential', [
          DropdownButtonFormField<String>(
            key: ValueKey('credential/$selectedId/${matching.length}'),
            initialValue:
                selectedId == '*' ||
                    matching.any((c) => b64(c.credential.id) == selectedId)
                ? selectedId
                : 'all',
            isExpanded: true,
            decoration: const InputDecoration(labelText: 'Allowed credential'),
            items: [
              const DropdownMenuItem(
                value: 'all',
                child: Text(
                  'All saved credentials',
                  style: TextStyle(fontSize: 15),
                ),
              ),
              const DropdownMenuItem(
                value: '*',
                child: Text(
                  'Discoverable credential',
                  style: TextStyle(fontSize: 15),
                ),
              ),
              for (final c in matching)
                DropdownMenuItem(
                  value: b64(c.credential.id),
                  child: Text(
                    '${c.username} · ${algorithmName(c.credential.publicKey.algorithmId)}',
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(fontSize: 15),
                  ),
                ),
            ],
            onChanged: busy
                ? null
                : (v) => _changed(() => selectedId = v == 'all' ? null : v),
          ),
          _select('Mediation', mediation, ['optional', 'conditional'], (v) {
            mediation = v;
            if (v == 'conditional') selectedId = '*';
          }),
          if (mediation == 'conditional') const PasskeyAutofill(),
        ]),
      _section(mode == 'create' ? '04' : '03', 'Authenticator selection', [
        _select('User verification', uv, [
          'preferred',
          'required',
          'discouraged',
        ], (v) => uv = v),
        if (mode == 'create') ...[
          _pair(
            _select('Discoverable credential', rk, [
              'preferred',
              'required',
              'discouraged',
            ], (v) => rk = v),
            _select('Attachment', attachment, [
              'any',
              'cross-platform',
              'platform',
            ], (v) => attachment = v),
          ),
          _select('Attestation', attestation, [
            'none',
            'direct',
            'indirect',
            'enterprise',
          ], (v) => attestation = v),
          CheckboxListTile(
            contentPadding: EdgeInsets.zero,
            dense: true,
            title: const Text(
              'Exclude all saved credentials for this RP',
              style: TextStyle(fontSize: 15),
            ),
            value: excludeExisting,
            onChanged: busy
                ? null
                : (v) => _changed(() => excludeExisting = v!),
          ),
        ],
        const Align(
          alignment: Alignment.centerLeft,
          child: Text('Authenticator hints', style: TextStyle(fontSize: 14)),
        ),
        Wrap(
          spacing: 6,
          runSpacing: 6,
          children: ['security-key', 'client-device', 'hybrid']
              .map(
                (hint) => FilterChip(
                  label: Text(hint, style: const TextStyle(fontSize: 14)),
                  selected: hints.contains(hint),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(4),
                  ),
                  onSelected: busy
                      ? null
                      : (v) => _changed(() {
                          if (v) {
                            hints.add(hint);
                          } else {
                            hints.remove(hint);
                          }
                        }),
                ),
              )
              .toList(),
        ),
      ]),
      _section(mode == 'create' ? '05' : '04', 'Request details', [
        _field(
          'Challenge · Base64URL',
          challenge,
          code: true,
          suffix: IconButton(
            tooltip: 'Generate challenge',
            onPressed: ready && !busy
                ? () => challenge.text = b64(RustCrypto.randomBytes(32))
                : null,
            icon: const Icon(Icons.refresh, size: 18),
          ),
        ),
        _field('Timeout · milliseconds', timeout, code: true),
      ]),
      _section(mode == 'create' ? '06' : '05', 'Extensions', [
        ExtensionsEditor(
          key: ValueKey(mode),
          controller: extensions,
          create: mode == 'create',
          enabled: ready && !busy,
          credentialIds: matching
              .where(
                (c) =>
                    selectedId != '*' &&
                    (selectedId == null || b64(c.credential.id) == selectedId),
              )
              .map((c) => b64(c.credential.id))
              .toList(),
        ),
        ExpansionTile(
          tilePadding: EdgeInsets.zero,
          title: const Text('Extension JSON', style: TextStyle(fontSize: 15)),
          children: [
            _field('Extensions · JSON', extensions, code: true, lines: 8),
            const SizedBox(height: 12),
          ],
        ),
      ]),
      const SizedBox(height: 18),
    ],
  );

  Widget _tabs(
    List<String> values,
    String selected,
    ValueChanged<String> onChanged,
  ) => Row(
    children: values
        .map(
          (v) => InkWell(
            onTap: () => onChanged(v),
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 17),
              decoration: BoxDecoration(
                border: Border(
                  bottom: BorderSide(
                    color: v == selected ? green : Colors.transparent,
                    width: 2,
                  ),
                ),
              ),
              child: Text(
                v,
                style: TextStyle(
                  fontSize: 15,
                  fontWeight: v == selected ? FontWeight.w600 : FontWeight.w400,
                  color: v == selected ? green : muted,
                ),
              ),
            ),
          ),
        )
        .toList(),
  );

  Widget _left() => ColoredBox(
    color: Colors.white,
    child: Column(
      children: [
        Container(
          decoration: const BoxDecoration(
            border: Border(bottom: BorderSide(color: line)),
          ),
          child: Row(
            children: [
              _tabs(['Form', 'JSON'], leftTab, (v) {
                if (!busy) _switchEditor(v);
              }),
              const Spacer(),
              IconButton(
                tooltip: 'Reset request',
                onPressed: ready && !busy ? _resetRequest : null,
                icon: const Icon(Icons.restart_alt, size: 18),
              ),
              IconButton(
                tooltip: 'Copy request',
                onPressed: () => _copy(requestJson.text),
                icon: const Icon(Icons.copy_outlined, size: 18),
              ),
              const SizedBox(width: 8),
            ],
          ),
        ),
        Expanded(
          child: SingleChildScrollView(
            child: leftTab == 'Form'
                ? _form()
                : Padding(
                    padding: const EdgeInsets.all(20),
                    child: _field(
                      'PublicKeyCredential options',
                      requestJson,
                      code: true,
                      lines: 35,
                    ),
                  ),
          ),
        ),
        Container(
          padding: const EdgeInsets.all(18),
          decoration: const BoxDecoration(
            border: Border(top: BorderSide(color: line)),
          ),
          child: Row(
            children: [
              Expanded(
                child: FilledButton.icon(
                  onPressed:
                      ready &&
                          !busy &&
                          env['webauthn'] == true &&
                          env['secure'] == true
                      ? _execute
                      : null,
                  icon: busy
                      ? const SizedBox(
                          width: 16,
                          height: 16,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : Icon(
                          mode == 'create' ? Icons.add : Icons.fingerprint,
                          size: 18,
                        ),
                  label: Text(
                    busy
                        ? 'Waiting for authenticator'
                        : mode == 'create'
                        ? 'Create credential'
                        : 'Authenticate',
                  ),
                ),
              ),
              if (busy) ...[
                const SizedBox(width: 8),
                IconButton(
                  tooltip: 'Cancel request',
                  onPressed: browser.cancelCeremony,
                  icon: const Icon(Icons.close),
                ),
              ],
            ],
          ),
        ),
      ],
    ),
  );

  Widget _code(String text) => Container(
    width: double.infinity,
    padding: const EdgeInsets.all(18),
    color: const Color(0xfff6f8f8),
    child: SelectableText(text, style: mono),
  );

  Widget _errorBox(String text) => Container(
    width: double.infinity,
    padding: const EdgeInsets.all(14),
    decoration: const BoxDecoration(
      color: Color(0xfffff0ed),
      border: Border(left: BorderSide(color: Color(0xffbf4c36), width: 3)),
    ),
    child: SelectableText(
      text,
      style: const TextStyle(
        color: Color(0xffa33d2b),
        fontSize: 14,
        height: 1.6,
      ),
    ),
  );
  Widget _empty(IconData icon, String title) => SizedBox(
    width: double.infinity,
    height: 200,
    child: Column(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        Icon(icon, size: 34, color: const Color(0xff9caeaa)),
        const SizedBox(height: 14),
        Text(title, style: const TextStyle(color: muted, fontSize: 16)),
      ],
    ),
  );

  Future<void> _importCredentials() async {
    final input = TextEditingController();
    String? error;
    final imported = await showDialog<List<SavedCredential>>(
      context: context,
      builder: (context) => StatefulBuilder(
        builder: (context, update) => AlertDialog(
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
          title: const Text('Import local credentials'),
          content: SizedBox(
            width: 560,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                TextField(
                  controller: input,
                  minLines: 5,
                  maxLines: 10,
                  style: mono,
                  decoration: const InputDecoration(
                    labelText: 'Credential export · JSON',
                  ),
                ),
                if (error != null)
                  Padding(
                    padding: const EdgeInsets.only(top: 12),
                    child: Text(
                      error!,
                      style: const TextStyle(color: Colors.red, fontSize: 14),
                    ),
                  ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: () {
                try {
                  if (input.text.length > 1000000) {
                    throw const FormatException('Import exceeds 1 MB');
                  }
                  final values = jsonDecode(input.text) as List;
                  if (values.length > 100) {
                    throw const FormatException(
                      'Maximum 100 credentials per import',
                    );
                  }
                  final records = values
                      .map(
                        (v) => SavedCredential.fromJson(
                          Map<String, dynamic>.from(v),
                        ),
                      )
                      .toList();
                  for (final saved in records) {
                    saved.credential.publicKey.validate();
                  }
                  Navigator.pop(context, records);
                } catch (e) {
                  update(() => error = '$e');
                }
              },
              child: const Text('Import'),
            ),
          ],
        ),
      ),
    );
    // The dialog's route may still be animating with this controller attached.
    if (imported == null || !mounted) return;
    setState(() {
      for (final saved in imported) {
        if (!credentials.any(
          (c) =>
              c.rpId == saved.rpId &&
              b64(c.credential.id) == b64(saved.credential.id),
        )) {
          credentials.add(saved);
        }
      }
    });
    _persist();
    _syncRequest();
    _notice(
      'Imported ${imported.length} records; existing credentials retained',
    );
  }

  Widget _credentialList() => SingleChildScrollView(
    padding: const EdgeInsets.all(24),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            const Text(
              'Saved credentials',
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.w600),
            ),
            const Spacer(),
            IconButton(
              tooltip: 'Import credentials',
              onPressed: ready && !busy ? _importCredentials : null,
              icon: const Icon(Icons.upload_outlined),
            ),
            IconButton(
              tooltip: 'Export credentials',
              onPressed: credentials.isEmpty
                  ? null
                  : () => browser.download(
                      'canokey-credentials.json',
                      pretty(credentials.map((c) => c.toJson()).toList()),
                    ),
              icon: const Icon(Icons.download_outlined),
            ),
          ],
        ),
        const SizedBox(height: 18),
        if (credentials.isEmpty)
          _empty(Icons.key_outlined, 'No credentials yet'),
        for (final saved in credentials)
          Container(
            margin: const EdgeInsets.only(bottom: 12),
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              border: Border.all(color: line),
              borderRadius: BorderRadius.circular(6),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    const Icon(Icons.key_outlined, color: green, size: 20),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Text(
                        saved.username,
                        style: const TextStyle(fontWeight: FontWeight.w600),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                    IconButton(
                      tooltip: 'Inspect public key',
                      onPressed: () {
                        showDialog<void>(
                          context: context,
                          builder: (context) => AlertDialog(
                            title: Text('${saved.username} · Public key'),
                            content: SizedBox(
                              width: 560,
                              child: SingleChildScrollView(
                                child: DecodedDataView(
                                  value: inspect(
                                    saved.toJson()['key'],
                                    'COSE key',
                                    'b64u',
                                    outputFormat,
                                    CoseConfiguration(sm2: saved.sm2),
                                  ),
                                ),
                              ),
                            ),
                            actions: [
                              TextButton(
                                onPressed: () => Navigator.pop(context),
                                child: const Text('Close'),
                              ),
                            ],
                          ),
                        );
                      },
                      icon: const Icon(Icons.data_object, size: 18),
                    ),
                    IconButton(
                      tooltip: 'Remove local credential',
                      onPressed: busy ? null : () => _remove(saved),
                      icon: const Icon(Icons.delete_outline, size: 18),
                    ),
                  ],
                ),
                Text(
                  '${saved.rpId} · ${algorithmName(saved.credential.publicKey.algorithmId)}',
                  style: const TextStyle(color: muted, fontSize: 14),
                ),
                const SizedBox(height: 10),
                Text(
                  b64(saved.credential.id),
                  style: mono,
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                ),
                const SizedBox(height: 10),
                Wrap(
                  spacing: 16,
                  runSpacing: 8,
                  children: [
                    Text(
                      'Counter ${saved.credential.signCount}',
                      style: const TextStyle(fontSize: 14),
                    ),
                    Text(
                      saved.credential.backedUp ? 'Backed up' : 'Not backed up',
                      style: const TextStyle(fontSize: 14, color: muted),
                    ),
                    TextButton.icon(
                      onPressed: busy
                          ? null
                          : () {
                              _switchMode('get');
                              _changed(() {
                                rp.text = saved.rpId;
                                selectedId = b64(saved.credential.id);
                              });
                            },
                      icon: const Icon(Icons.fingerprint, size: 16),
                      label: const Text('Authenticate'),
                    ),
                  ],
                ),
              ],
            ),
          ),
      ],
    ),
  );

  Future<void> _remove(SavedCredential saved) async {
    final index = credentials.indexOf(saved);
    setState(() {
      credentials.remove(saved);
      if (selectedId == b64(saved.credential.id)) selectedId = null;
    });
    _persist();
    _syncRequest();
    _notice(
      'Local credential removed',
      action: SnackBarAction(
        label: 'Undo',
        onPressed: () {
          setState(
            () => credentials.insert(index.clamp(0, credentials.length), saved),
          );
          _persist();
          _syncRequest();
        },
      ),
    );
  }

  void _persist() {
    try {
      browser.saveCredentials(
        jsonEncode(credentials.map((c) => c.toJson()).toList()),
      );
    } catch (e) {
      _notice('Local save failed: $e');
    }
  }

  Widget _history() => ListView(
    padding: const EdgeInsets.all(24),
    children: [
      const Text(
        'Ceremony history',
        style: TextStyle(fontSize: 18, fontWeight: FontWeight.w600),
      ),
      const SizedBox(height: 20),
      if (history.isEmpty) _empty(Icons.history, 'No requests yet'),
      for (final entry in history)
        ListTile(
          contentPadding: EdgeInsets.zero,
          leading: Icon(
            entry['verified'] == true
                ? Icons.check_circle_outline
                : Icons.error_outline,
            color: entry['verified'] == true ? green : const Color(0xffb34c35),
          ),
          title: Text(
            '${entry['operation'] == 'create' ? 'Create' : 'Assert'} · ${entry['durationMs']} ms',
            style: const TextStyle(fontSize: 16),
          ),
          subtitle: Text(
            entry['result'],
            maxLines: 3,
            overflow: TextOverflow.ellipsis,
            style: const TextStyle(fontSize: 14),
          ),
          trailing: IconButton(
            tooltip: 'Export request report',
            onPressed: () =>
                browser.download('webauthn-report.json', pretty(entry)),
            icon: const Icon(Icons.download_outlined, size: 18),
          ),
          onTap: () {
            setState(() {
              lastReport = entry;
              rightTab = 'Result';
            });
          },
        ),
    ],
  );

  Widget _extensionResults() {
    final report = lastReport;
    final response = report?['response'] as Map<String, dynamic>?;
    if (response == null) {
      return _empty(Icons.extension_outlined, 'No extension results yet');
    }
    final request = report?['request'] as Map? ?? {};
    final requested = request['extensions'] as Map? ?? {};
    final client = response['clientExtensionResults'] as Map? ?? {};
    Object? authenticator;
    String? error;
    try {
      authenticator = jsonValue(
        AuthenticatorData.parse(
          responseAuthenticatorData(response),
          configuration: _reportConfiguration(report!),
        ).extensions,
        format: outputFormat,
      );
    } catch (e) {
      error = '$e';
    }
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('${report!['time']} · ${report['operation']}'),
          const SizedBox(height: 12),
          const Text(
            'Extension results',
            style: TextStyle(fontSize: 18, fontWeight: FontWeight.w600),
          ),
          const SizedBox(height: 20),
          for (final key in requested.keys)
            Padding(
              padding: const EdgeInsets.only(bottom: 12),
              child: Row(
                children: [
                  Expanded(
                    child: Text('$key', style: const TextStyle(fontSize: 14)),
                  ),
                  const SizedBox(width: 12),
                  Text(
                    client.containsKey(key) ? 'Returned' : 'No client output',
                    style: TextStyle(
                      fontSize: 13,
                      color: client.containsKey(key) ? green : muted,
                    ),
                  ),
                ],
              ),
            ),
          const SizedBox(height: 12),
          _select('Binary output', outputFormat, [
            'hex',
            'b64',
            'b64u',
          ], (v) => outputFormat = v),
          const SizedBox(height: 24),
          const Text(
            'Client outputs',
            style: TextStyle(fontWeight: FontWeight.w600),
          ),
          const SizedBox(height: 10),
          _code(pretty(inspectClientExtensions(client, outputFormat))),
          const SizedBox(height: 24),
          const Text(
            'Authenticator outputs',
            style: TextStyle(fontWeight: FontWeight.w600),
          ),
          const SizedBox(height: 10),
          if (error != null)
            _errorBox(error)
          else
            _code(pretty(authenticator ?? {})),
          const SizedBox(height: 24),
          const Text(
            'Requested extensions',
            style: TextStyle(fontWeight: FontWeight.w600),
          ),
          const SizedBox(height: 10),
          _code(pretty(requested)),
        ],
      ),
    );
  }

  CoseConfiguration _reportConfiguration(Map<String, dynamic> report) {
    final profile = report['inspectionProfile'] as Map?;
    return CoseConfiguration(
      sm2: profile == null
          ? null
          : Sm2Configuration(
              algorithm: profile['algorithm'],
              curve: profile['curve'],
              allowUnassignedIdentifiers: true,
            ),
    );
  }

  Widget _resultView() {
    final report = lastReport;
    if (report == null) {
      return _empty(
        Icons.data_object,
        busy ? 'Waiting for authenticator' : 'No request selected',
      );
    }
    Object? result;
    String? error;
    if (report['response'] != null) {
      try {
        result = inspect(
          pretty(report['response']),
          'Credential JSON',
          'b64u',
          outputFormat,
          _reportConfiguration(report),
        );
      } catch (e) {
        error = '$e';
      }
    }
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'Request result',
            style: TextStyle(fontSize: 18, fontWeight: FontWeight.w600),
          ),
          const SizedBox(height: 12),
          Text('${report['time']} · ${report['operation']}'),
          const SizedBox(height: 12),
          Text('${report['result']}'),
          if (report['operation'] == 'create' && report['verified'] == true)
            const Text('Certificate-chain trust is not evaluated.'),
          const SizedBox(height: 16),
          Wrap(
            spacing: 8,
            children: [
              for (final format in ['hex', 'b64', 'b64u'])
                ChoiceChip(
                  label: Text(format),
                  selected: outputFormat == format,
                  onSelected: (_) => setState(() => outputFormat = format),
                ),
            ],
          ),
          if (error != null) _errorBox(error),
          if (result != null) DecodedDataView(value: result),
          if (report['response'] == null)
            const Text('No authenticator response was returned.'),
        ],
      ),
    );
  }

  Widget _right() => ColoredBox(
    color: Colors.white,
    child: Column(
      children: [
        Container(
          decoration: const BoxDecoration(
            border: Border(bottom: BorderSide(color: line)),
          ),
          child: SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: _tabs(
              ['Result', 'Extensions', 'Response', 'Credentials', 'History'],
              rightTab,
              (v) => setState(() => rightTab = v),
            ),
          ),
        ),
        Expanded(
          child: switch (rightTab) {
            'Result' => _resultView(),
            'Extensions' => _extensionResults(),
            'Credentials' => _credentialList(),
            'History' => _history(),
            _ => SingleChildScrollView(
              padding: const EdgeInsets.all(24),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const Text(
                        'Raw response',
                        style: TextStyle(
                          fontSize: 18,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      const Spacer(),
                      IconButton(
                        tooltip: 'Copy response',
                        onPressed: rawResponse.isEmpty
                            ? null
                            : () => _copy(rawResponse),
                        icon: const Icon(Icons.copy_outlined, size: 18),
                      ),
                      IconButton(
                        tooltip: 'Export report',
                        onPressed: lastReport == null
                            ? null
                            : () => browser.download(
                                'webauthn-report.json',
                                pretty(lastReport),
                              ),
                        icon: const Icon(Icons.download_outlined, size: 18),
                      ),
                    ],
                  ),
                  const SizedBox(height: 16),
                  if (lastReport != null)
                    Text('${lastReport!['time']} · ${lastReport!['result']}'),
                  if (rawResponse.isEmpty)
                    _empty(Icons.receipt_long_outlined, 'No response yet')
                  else
                    _code(rawResponse),
                ],
              ),
            ),
          },
        ),
      ],
    ),
  );

  @override
  Widget build(BuildContext context) => Scaffold(
    body: SafeArea(
      child: LayoutBuilder(
        builder: (context, box) {
          final wide = box.maxWidth >= 900;
          return Column(
            children: [
              Container(
                height: 70,
                padding: EdgeInsets.symmetric(horizontal: wide ? 30 : 16),
                decoration: const BoxDecoration(
                  color: Colors.white,
                  border: Border(bottom: BorderSide(color: line)),
                ),
                child: Row(
                  children: [
                    Container(
                      width: 34,
                      height: 34,
                      decoration: BoxDecoration(
                        color: green,
                        borderRadius: BorderRadius.circular(6),
                      ),
                      child: const Icon(
                        Icons.key,
                        size: 22,
                        color: Colors.white,
                      ),
                    ),
                    const SizedBox(width: 12),
                    const Text(
                      'CanoKey',
                      style: TextStyle(
                        fontSize: 22,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                    if (wide) ...[
                      const SizedBox(width: 20),
                      Container(height: 20, width: 1, color: line),
                      const SizedBox(width: 20),
                      const Text(
                        'WebAuthn Workbench',
                        style: TextStyle(color: muted, fontSize: 16),
                      ),
                    ],
                  ],
                ),
              ),
              ColoredBox(
                color: Colors.white,
                child: _tabs(
                  ['Workbench', 'Inspector'],
                  workspace,
                  (value) => setState(() => workspace = value),
                ),
              ),
              Expanded(
                child: IndexedStack(
                  index: workspace == 'Workbench' ? 0 : 1,
                  children: [
                    Column(
                      children: [
                        Container(
                          padding: EdgeInsets.fromLTRB(
                            wide ? 30 : 16,
                            18,
                            wide ? 30 : 16,
                            16,
                          ),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Row(
                                children: [
                                  SegmentedButton<String>(
                                    segments: const [
                                      ButtonSegment(
                                        value: 'create',
                                        label: Text('Create'),
                                        icon: Icon(Icons.add, size: 18),
                                      ),
                                      ButtonSegment(
                                        value: 'get',
                                        label: Text('Assert'),
                                        icon: Icon(Icons.fingerprint, size: 18),
                                      ),
                                    ],
                                    selected: {mode},
                                    onSelectionChanged: busy
                                        ? null
                                        : (v) => _switchMode(v.first),
                                    showSelectedIcon: false,
                                    style: const ButtonStyle(
                                      visualDensity: VisualDensity.compact,
                                    ),
                                  ),
                                  const Spacer(),
                                  if (!ready && statusError)
                                    IconButton(
                                      tooltip: 'Retry',
                                      onPressed: _initialize,
                                      icon: const Icon(Icons.refresh, size: 18),
                                    ),
                                ],
                              ),
                              if (status.isNotEmpty)
                                Padding(
                                  padding: const EdgeInsets.only(top: 12),
                                  child: statusError
                                      ? _errorBox(status)
                                      : Container(
                                          width: double.infinity,
                                          padding: const EdgeInsets.all(12),
                                          color: const Color(0xffe5f3ed),
                                          child: Text(
                                            status,
                                            style: const TextStyle(
                                              fontSize: 14,
                                              color: green,
                                            ),
                                          ),
                                        ),
                                ),
                            ],
                          ),
                        ),
                        Expanded(
                          child: wide
                              ? Padding(
                                  padding: const EdgeInsets.fromLTRB(
                                    30,
                                    0,
                                    30,
                                    20,
                                  ),
                                  child: Row(
                                    crossAxisAlignment:
                                        CrossAxisAlignment.stretch,
                                    children: [
                                      SizedBox(
                                        width: (box.maxWidth * .38).clamp(
                                          360,
                                          510,
                                        ),
                                        child: _left(),
                                      ),
                                      const SizedBox(width: 1),
                                      Expanded(child: _right()),
                                    ],
                                  ),
                                )
                              : ListView(
                                  children: [
                                    SizedBox(height: 670, child: _left()),
                                    const SizedBox(height: 16),
                                    SizedBox(height: 740, child: _right()),
                                  ],
                                ),
                        ),
                      ],
                    ),
                    Align(
                      alignment: Alignment.topCenter,
                      child: ConstrainedBox(
                        constraints: const BoxConstraints(maxWidth: 1100),
                        child: const ColoredBox(
                          color: Colors.white,
                          child: InspectorPanel(),
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          );
        },
      ),
    ),
  );
}
