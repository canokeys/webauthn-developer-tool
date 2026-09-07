import 'dart:js_interop';

@JS('workbench.environment')
external JSString _environment();
@JS('workbench.perform')
external JSPromise<JSString> _perform(
  JSString kind,
  JSString options,
  JSString mediation,
);
@JS('workbench.cancel')
external void _cancelCeremony();
@JS('workbench.read')
external JSString _read();
@JS('workbench.save')
external void _save(JSString json);
@JS('workbench.download')
external void _download(JSString name, JSString contents);

String environment() => _environment().toDart;
void cancelCeremony() => _cancelCeremony();
Future<String> perform(
  String kind,
  String options, {
  String mediation = 'optional',
}) async =>
    (await _perform(kind.toJS, options.toJS, mediation.toJS).toDart).toDart;
String readCredentials() => _read().toDart;
void saveCredentials(String json) => _save(json.toJS);
void download(String name, String contents) =>
    _download(name.toJS, contents.toJS);
