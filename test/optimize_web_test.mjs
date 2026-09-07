import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, access, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import vm from 'node:vm';
import { optimizeWeb } from '../scripts/optimize-web.mjs';

async function fixture(t, compileTarget = 'dart2js') {
  const output = await mkdtemp(path.join(os.tmpdir(), 'canokey-web-'));
  t.after(() => rm(output, { recursive: true, force: true }));
  for (const variant of ['', 'chromium', 'webparagraph']) {
    const directory = path.join(output, 'canvaskit', variant);
    await mkdir(directory, { recursive: true });
    await writeFile(path.join(directory, 'canvaskit.js'), `// ${variant}`);
    await writeFile(path.join(directory, 'canvaskit.wasm'), `wasm ${variant}`);
    await writeFile(path.join(directory, 'canvaskit.js.symbols'), 'symbols'.repeat(100));
  }
  for (const name of ['skwasm', 'skwasm_heavy', 'wimp']) {
    for (const ext of ['js', 'wasm']) {
      await writeFile(path.join(output, 'canvaskit', `${name}.${ext}`), 'unused'.repeat(100));
    }
  }
  const config = { useLocalCanvasKit: true, builds: [{ compileTarget, renderer: 'canvaskit' }] };
  await writeFile(path.join(output, 'flutter_bootstrap.js'),
    `_flutter.buildConfig = ${JSON.stringify(config)};\n_flutter.loader.load();\n`);
  await writeFile(path.join(output, '_headers'), '/index.html\n  Cache-Control: no-cache\n');
  return output;
}

test('prunes unused engines, preserves all CanvasKit variants and configures versioned caching', async t => {
  const output = await fixture(t);
  const { before, after, baseUrl } = await optimizeWeb(output);
  assert.ok(after < before);
  assert.match(baseUrl, /^engine-assets\/[a-f0-9]{64}\/$/);
  let options;
  vm.runInNewContext(await readFile(path.join(output, 'flutter_bootstrap.js'), 'utf8'), {
    _flutter: { loader: { load(value) { options = value; } } },
  });
  assert.equal(options.config.canvasKitBaseUrl, baseUrl);
  for (const variant of ['', 'chromium', 'webparagraph']) {
    for (const ext of ['js', 'wasm']) {
      await access(path.join(output, baseUrl, variant, `canvaskit.${ext}`));
    }
    await assert.rejects(access(path.join(output, baseUrl, variant, 'canvaskit.js.symbols')));
  }
  await assert.rejects(access(path.join(output, 'canvaskit')));
  await assert.rejects(access(path.join(output, baseUrl, 'skwasm.wasm')));
  const headers = await readFile(path.join(output, '_headers'), 'utf8');
  assert.match(headers, /\/index.html\n  Cache-Control: no-cache/);
  assert.match(headers, /\/engine-assets\/\*\n  Cache-Control: public, max-age=31536000, immutable/);
});

test('engine URLs are stable across identical builds and change when engine content changes', async t => {
  const first = await fixture(t);
  const second = await fixture(t);
  const third = await fixture(t);
  await writeFile(path.join(third, 'canvaskit', 'canvaskit.wasm'), 'new engine');
  const a = await optimizeWeb(first);
  const b = await optimizeWeb(second);
  const c = await optimizeWeb(third);
  assert.equal(a.baseUrl, b.baseUrl);
  assert.notEqual(a.baseUrl, c.baseUrl);
});

test('rejects a WASM app build before removing its required engines', async t => {
  const output = await fixture(t, 'dart2wasm');
  await assert.rejects(optimizeWeb(output), /Expected an unmodified/);
  await access(path.join(output, 'canvaskit', 'skwasm.wasm'));
});

test('rebuilding replaces previous engine assets without duplicating cache rules', async t => {
  const output = await fixture(t);
  const bootstrap = await readFile(path.join(output, 'flutter_bootstrap.js'), 'utf8');
  const first = await optimizeWeb(output);
  const { cp } = await import('node:fs/promises');
  await cp(path.join(output, first.baseUrl), path.join(output, 'canvaskit'), { recursive: true });
  await writeFile(path.join(output, 'flutter_bootstrap.js'), bootstrap);
  const second = await optimizeWeb(output);
  assert.equal(first.baseUrl, second.baseUrl);
  await access(path.join(output, second.baseUrl, 'canvaskit.wasm'));
  const headers = await readFile(path.join(output, '_headers'), 'utf8');
  assert.equal(headers.split('/engine-assets/*').length, 2);
});
