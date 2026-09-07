const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');

function setup(call, conditional = false) {
  const context = vm.createContext({Uint8Array, ArrayBuffer, Object, JSON, String, TypeError, Error, atob, btoa, structuredClone, AbortController, isSecureContext: true, PublicKeyCredential: class { static async isConditionalMediationAvailable() { return conditional; } }, navigator: {credentials: {create: call, get: call}}});
  vm.runInContext(fs.readFileSync('web/webauthn.js', 'utf8'), context);
  return context.workbench;
}
const encoded = bytes => Buffer.from(bytes).toString('base64url');
test('create preserves algorithm order and converts binary extensions', async () => {
  const bridge = setup(async ({publicKey}) => {
    assert.deepEqual([...publicKey.challenge], [0, 255]);
    assert.deepEqual([...publicKey.user.id], [1]);
    assert.deepEqual(publicKey.pubKeyCredParams.map(v => v.alg), [-65537, -48]);
    assert.deepEqual([...publicKey.extensions.prf.eval.first], [8]);
    return {id: 'AQ', rawId: new Uint8Array([1]).buffer, type: 'public-key', response: {clientDataJSON: new Uint8Array([2]).buffer, attestationObject: new Uint8Array([3]).buffer, getTransports: () => ['usb']}, getClientExtensionResults: () => ({prf: {results: {first: new Uint8Array([9]).buffer}}})};
  });
  const response = JSON.parse(await bridge.perform('create', JSON.stringify({challenge: encoded([0,255]), user: {id: 'AQ'}, pubKeyCredParams: [{alg: -65537}, {alg: -48}], extensions: {prf: {eval: {first: 'CA'}}}})));
  assert.equal(response.response.attestationObject, 'Aw');
  assert.equal(response.clientExtensionResults.prf.results.first, 'CQ');
});
test('assert converts allowCredentials and nullable userHandle', async () => {
  const bridge = setup(async ({publicKey}) => {
    assert.deepEqual([...publicKey.allowCredentials[0].id], [1]);
    return {id: 'AQ', rawId: new Uint8Array([1]).buffer, type: 'public-key', response: {clientDataJSON: new Uint8Array([2]).buffer, authenticatorData: new Uint8Array([3]).buffer, signature: new Uint8Array([4]).buffer, userHandle: null}, getClientExtensionResults: () => ({})};
  });
  const response = JSON.parse(await bridge.perform('get', JSON.stringify({challenge: 'AQ', allowCredentials: [{id: 'AQ', type: 'public-key'}]})));
  assert.equal(response.response.userHandle, null);
  assert.equal(response.response.signature, 'BA');
});
test('cancel aborts a request and allows a subsequent request', async () => {
  const bridge = setup(({signal}) => new Promise((resolve, reject) => signal.addEventListener('abort', () => reject(new DOMException('Cancelled', 'AbortError')))));
  const pending = bridge.perform('get', '{"challenge":"AQ"}');
  await assert.rejects(bridge.perform('get', '{"challenge":"AQ"}'), /already running/);
  bridge.cancel();
  await assert.rejects(pending, /AbortError/);
  const next = bridge.perform('get', '{"challenge":"AQ"}'); bridge.cancel();
  await assert.rejects(next, /AbortError/);
});

test('largeBlob and per-credential PRF convert empty and nonempty bytes', async () => {
  const bridge = setup(async ({publicKey, mediation}) => {
    assert.equal(mediation, 'optional');
    assert.deepEqual([...publicKey.extensions.largeBlob.write], []);
    assert.deepEqual([...publicKey.extensions.prf.evalByCredential.AQ.first], []);
    assert.deepEqual([...publicKey.extensions.prf.evalByCredential.AQ.second], [0,255]);
    assert.equal(publicKey.allowCredentials[0].transports[0], 'hybrid');
    assert.deepEqual(publicKey.hints, ['security-key','hybrid']);
    return {id:'AQ',rawId:new Uint8Array([1]).buffer,type:'public-key',response:{clientDataJSON:new Uint8Array().buffer,authenticatorData:new Uint8Array().buffer,signature:new Uint8Array().buffer,userHandle:null},getClientExtensionResults:()=>({largeBlob:{written:false,blob:new Uint8Array([9]).buffer},prf:{results:{first:new Uint8Array([0,255]).buffer}}})};
  });
  const result = JSON.parse(await bridge.perform('get', JSON.stringify({challenge:'AQ',hints:['security-key','hybrid'],allowCredentials:[{id:'AQ',transports:['hybrid']}],extensions:{largeBlob:{write:''},prf:{evalByCredential:{AQ:{first:'',second:'AP8'}}}}})));
  assert.equal(result.clientExtensionResults.largeBlob.written,false);
  assert.equal(result.clientExtensionResults.largeBlob.blob,'CQ');
  assert.equal(result.clientExtensionResults.prf.results.first,'AP8');
});
test('conditional mediation is passed outside publicKey and remains cancellable', async () => {
  let started;
  const startedPromise = new Promise(resolve => { started = resolve; });
  const bridge = setup(({publicKey,mediation,signal}) => new Promise((resolve,reject) => {
    assert.equal(mediation,'conditional'); assert.equal(publicKey.mediation,undefined);
    signal.addEventListener('abort',()=>reject(new DOMException('Cancelled','AbortError'))); started();
  }),true);
  const pending = bridge.perform('get','{"challenge":"AQ","allowCredentials":[]}', 'conditional');
  await startedPromise; bridge.cancel(); await assert.rejects(pending,/AbortError/);
});
test('unavailable conditional mediation produces an actionable error without a prompt', async () => {
  const bridge = setup(() => assert.fail('Should not open a prompt'));
  await assert.rejects(bridge.perform('get','{"challenge":"AQ"}','conditional'),/autofill is unavailable/);
});
