/* Binary conversions live at the browser boundary; Dart receives JSON only. */
(() => {
  const decode = (value) => {
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*={0,2}$/.test(value)) throw new TypeError('Expected a Base64URL string');
    return Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
  };
  const encode = (value) => {
    const bytes = value instanceof ArrayBuffer ? new Uint8Array(value) : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    let text = '';
    for (const byte of bytes) text += String.fromCharCode(byte);
    return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  const serialize = (value) => {
    if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) return encode(value);
    if (Array.isArray(value)) return value.map(serialize);
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k,v]) => [k, serialize(v)]));
    return value;
  };
  function optionsFromJSON(kind, input) {
    const key = structuredClone(input);
    key.challenge = decode(key.challenge);
    if (kind === 'create') key.user.id = decode(key.user.id);
    for (const field of ['allowCredentials', 'excludeCredentials']) {
      if (key[field]) key[field] = key[field].map(c => ({...c, id: decode(c.id)}));
    }
    const ext = key.extensions;
    if (ext?.largeBlob && 'write' in ext.largeBlob) ext.largeBlob.write = decode(ext.largeBlob.write);
    if (ext && 'credBlob' in ext) ext.credBlob = decode(ext.credBlob);
    const convertPRF = (values) => {
      if (values && 'first' in values) values.first = decode(values.first);
      if (values && 'second' in values) values.second = decode(values.second);
    };
    convertPRF(ext?.prf?.eval);
    for (const values of Object.values(ext?.prf?.evalByCredential ?? {})) convertPRF(values);
    return key;
  }
  let active;
  globalThis.workbench = {
    environment: () => JSON.stringify({origin: location.origin, hostname: location.hostname, secure: isSecureContext, webauthn: typeof PublicKeyCredential !== 'undefined'}),
    cancel: () => active?.abort(),
    async perform(kind, json, mediation = 'optional') {
      if (active) throw new Error('A ceremony is already running');
      if (!isSecureContext || typeof PublicKeyCredential === 'undefined') throw new Error('WebAuthn requires a secure context and browser support');
      active = new AbortController();
      try {
        const publicKey = optionsFromJSON(kind, JSON.parse(json));
        if (!['optional', 'conditional'].includes(mediation) || (kind === 'create' && mediation !== 'optional')) throw new TypeError('Invalid mediation mode');
        if (mediation === 'conditional' && !await PublicKeyCredential.isConditionalMediationAvailable?.()) throw new Error('Passkey autofill is unavailable in this browser');
        const credential = await navigator.credentials[kind]({publicKey, mediation, signal: active.signal});
        if (!credential) throw new Error('No credential returned');
        const r = credential.response;
        const response = {clientDataJSON: encode(r.clientDataJSON)};
        if (kind === 'create') {
          response.attestationObject = encode(r.attestationObject);
          response.transports = r.getTransports?.() ?? [];
          if (r.getPublicKeyAlgorithm) response.publicKeyAlgorithm = r.getPublicKeyAlgorithm();
        } else {
          response.authenticatorData = encode(r.authenticatorData);
          response.signature = encode(r.signature);
          response.userHandle = r.userHandle ? encode(r.userHandle) : null;
        }
        return JSON.stringify({id: credential.id, rawId: encode(credential.rawId), type: credential.type, authenticatorAttachment: credential.authenticatorAttachment, response, clientExtensionResults: serialize(credential.getClientExtensionResults())});
      } catch (error) {
        throw new Error(`${error.name || 'Error'}: ${error.message}`);
      } finally { active = undefined; }
    },
    read: () => localStorage.getItem('canokey.workbench.v1') ?? '[]',
    save: (json) => localStorage.setItem('canokey.workbench.v1', json),
    download(name, contents) {
      const url = URL.createObjectURL(new Blob([contents], {type: 'application/json'}));
      const a = document.createElement('a'); a.href = url; a.download = name; a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    },
  };
})();
