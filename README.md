# CanoKey WebAuthn Workbench

Flutter Web developer tool inspired by Yubico's WebAuthn developer page. Uses
`navigator.credentials.create/get` and the **fido2 2.0.1** library for
COSE parsing and WebAuthn validation. No desktop client, WebUSB, or local bridge.

## Run

Requires Flutter/Dart 3.9+, Rust and wasm-pack. Dependencies resolve from pub.dev.

```sh
flutter pub get
dart run fido2:setup --web --output=web/crypto
flutter run -d web-server --web-hostname localhost --web-port 8080
```

Open http://localhost:8080. Production: https://dev.canokeys.org.
Use localhost for development and HTTPS for deployment.
The RP ID defaults to the current hostname. User presence/PIN interactions are
handled by the browser's native WebAuthn prompt.

## Build

```sh
npm ci
npm run build
```

Deploy `build/web/` including `crypto/web/`. Serve `.wasm` as `application/wasm`.
Crypto assets are generated and ignored by Git. `web/index.html` loads the
library's JS loader before Flutter; the application initializes its WASM module.

After upgrading fido2, rebuild the crypto assets using the same command.

## Cloudflare Workers

The `webauthn-developer-tool` Worker serves `build/web` using Workers Static
Assets. `wrangler.jsonc` binds the custom domain `dev.canokeys.org`; Cloudflare
manages its DNS record and TLS certificate. The canokeys.org zone must be in the
Cloudflare account used for deployment.

With Flutter, Rust, wasm-pack and Node.js installed:

```sh
npm ci
npx wrangler login
npm run deploy
```

The deployment command regenerates fido2 WASM assets and builds Flutter with
locally served CanvasKit resources before publishing. To check an existing
build locally with Workers, run `npm run preview`. Generated assets, build
output and Cloudflare credentials are excluded from Git.

The build removes unused Skwasm/Wimp engines and engine symbol files, retaining
all CanvasKit browser variants. Engine URLs include a content hash and receive
one-year immutable caching through Workers Static Assets. Application entrypoints
retain Cloudflare's default revalidation policy so new deployments take effect.
Run the complete `npm run build` pipeline before deploying; its final optimization
step expects the repository's JS/CanvasKit bootstrap and rejects other build modes.

Workers Builds is connected to `canokeys/webauthn-developer-tool`, production
branch `main`, with root directory `/`. Set its build command to
`npm run build:cloudflare` and deploy command to `npx wrangler deploy`.
The build script installs Flutter 3.47.2 and the Rust/WASM toolchain; wasm-pack
is pinned in npm dependencies. Pushes to `main` then build and deploy the site.

The RP ID follows the hostname, so production credentials are scoped to
`dev.canokeys.org`. Localhost credentials cannot be reused on that domain.

## Scope

- Create/Assert with form and JSON options, ordered algorithms, RK/UV,
  attachment, attestation, extensions, timeout, allow/exclude credentials.
  Registration defaults to an empty `excludeCredentials` list for repeated
  testing on the same key. Enabling the exclusion checkbox includes every saved
  credential for the RP, regardless of user ID; a key containing any of them
  will reject registration with `InvalidStateError`. With discoverable
  credentials, reusing the same RP and user ID may replace a device credential;
  use a new WebAuthn user ID when testing separate accounts.
- ES256, Ed25519, SM2 and ML-DSA-44/65/87, through fido2's Rust/WASM backend.
- SM2 uses explicit algorithm/curve IDs, fixed `raw` signature encoding
  (64 bytes, two 32-byte integers `r || s`), and the default SM2 user ID
  `1234567812345678` used to calculate ZA. This is separate from the editable
  WebAuthn user ID. These verification parameters must match the authenticator; standard
  WebAuthn does not send an SM2 user ID or signature encoding to the device.
  Registration saves the SM2 verification profile with the credential, and
  assertions reuse that saved profile.
  The default profile matches CanoKey: algorithm ID `-54`, curve ID `9`; set the profile matching
  the credential being tested. The library assigns `-48` to ML-DSA-44 and rejects
  that identifier for SM2.
- Extension controls for credProps, minPinLength, credProtect/enforcement,
  largeBlob support/read/write, and PRF evaluation including per-credential inputs.
  Create and Assert keep separate extension options; advanced JSON preserves
  additional fields. Large blob writes require exactly one allowed credential.
- Ordered authenticator hints, persisted credential transports, and conditional
  mediation with a native `autocomplete="username webauthn"` input.
- Extension results distinguish client output from authenticator output and show
  returned bytes as hex/Base64/Base64URL. Missing output is reported explicitly.
- Inspector for credentials, client/authenticator data, attestation objects,
  COSE keys, CBOR and JSON, with hex/Base64/Base64URL views.
- Verified registrations persist locally. Credentials support export/import,
  local removal with undo, assertion verification, and counter updates.
- Execution history and request/response report export. Challenges rotate after
  every attempt. The exact request and verification policy are captured before
  calling the browser.

This is a local developer session, not an authentication backend. Public keys,
user handles and counters are kept in localStorage; private keys remain with the
authenticator. Imported keys are explicitly user-provided trust data. History
and raw responses remain in memory unless exported. There is no account server
or telemetry. The Workers deployment build serves CanvasKit from the same origin.

The library completes registration for `fmt=none` and `fmt=packed`, including
packed certificate and self attestation. Packed signatures and supported leaf
certificate profiles are verified before credentials are saved. This app does
not implement certificate trust-chain verification: successful registration does
not establish trust in the authenticator vendor. Other attestation formats remain
available for inspection and export but are not saved as verified credentials.
Actual WebAuthn algorithm availability is determined by the browser/authenticator;
an unsupported algorithm or cancelled prompt is reported as an error.

These are WebAuthn options compatible with the current fido2 verifier, not a full
CTAP 2.3 implementation. Experimental previewSign/sign is not included. Requesting
an extension does not guarantee support. Client extension results are not generally
covered by the authenticator signature; assertion authenticator extensions are
inside the signed authenticator data. Successful primary verification does not
alone establish that an extension succeeded.

## Tests

```sh
dart run fido2:setup
FIDO2_CRYPTO_LIBRARY="$PWD/build/fido2/native/release/libfido2_crypto.dylib" flutter test
node --test test/browser_bridge_test.cjs
node --test test/optimize_web_test.mjs
flutter analyze
```

Use the corresponding `.so`/`.dll` on Linux/Windows. Integration fixtures exercise
registration, credential persistence, assertion verification and tampering for
all six algorithms. Bridge tests cover browser binary conversion, algorithm
ordering, PRF/largeBlob encoding, conditional mediation and cancellation. Form
tests cover JSON synchronization; validation tests cover extension constraints.
These tests do not substitute for
physical authenticator testing.
