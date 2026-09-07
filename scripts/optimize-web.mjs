import { createHash } from 'node:crypto';
import { readdir, readFile, writeFile, rm, mkdir, rename, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

async function filesIn(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const name = path.join(directory, entry.name);
    files.push(...(entry.isDirectory() ? await filesIn(name) : [name]));
  }
  return files.sort();
}

async function sizeOf(directory) {
  let size = 0;
  for (const file of await filesIn(directory)) size += (await stat(file)).size;
  return size;
}

export async function optimizeWeb(output = 'build/web') {
  const bootstrapPath = path.join(output, 'flutter_bootstrap.js');
  const bootstrap = await readFile(bootstrapPath, 'utf8');
  const configMatch = bootstrap.match(/^_flutter\.buildConfig = (.+);$/m);
  const config = configMatch && JSON.parse(configMatch[1]);
  const loadCall = '_flutter.loader.load();';
  // Fail before pruning if a Flutter upgrade changes the build or loader contract.
  if (!config?.useLocalCanvasKit || !config.builds?.length ||
      !config.builds.every(build => build.compileTarget === 'dart2js' && build.renderer === 'canvaskit') ||
      bootstrap.split(loadCall).length !== 2) {
    throw new Error('Expected an unmodified Flutter JS/CanvasKit build with local engine assets.');
  }
  // Flutter preserves extra output files on incremental builds.
  await rm(path.join(output, 'engine-assets'), { recursive: true, force: true });
  const before = await sizeOf(output);
  const engine = path.join(output, 'canvaskit');
  for (const file of await filesIn(engine)) {
    const name = path.basename(file);
    if (name.endsWith('.symbols') || /^(skwasm(?:_heavy)?|wimp)\.(js|wasm)$/.test(name)) {
      await rm(file);
    }
  }

  // Hash all retained variants together so each URL can be cached across releases.
  const hash = createHash('sha256');
  for (const file of await filesIn(engine)) {
    hash.update(path.relative(engine, file).split(path.sep).join('/'));
    hash.update('\0');
    hash.update(await readFile(file));
  }
  const baseUrl = `engine-assets/${hash.digest('hex')}/`;
  await mkdir(path.join(output, 'engine-assets'), { recursive: true });
  await rename(engine, path.join(output, baseUrl));
  await writeFile(bootstrapPath, bootstrap.replace(loadCall,
    `_flutter.loader.load(${JSON.stringify({ config: { canvasKitBaseUrl: baseUrl } })});`));

  const headersPath = path.join(output, '_headers');
  const headers = await readFile(headersPath, 'utf8').catch(error => {
    if (error.code !== 'ENOENT') throw error;
    return '';
  });
  const cacheRule = '\n/engine-assets/*\n  Cache-Control: public, max-age=31536000, immutable\n';
  await writeFile(headersPath, headers.replaceAll(cacheRule, '') + cacheRule);
  const after = await sizeOf(output);
  console.log(`Web assets: ${(before / 1048576).toFixed(2)} MiB -> ${(after / 1048576).toFixed(2)} MiB (${((before - after) / before * 100).toFixed(1)}% smaller)`);
  return { before, after, baseUrl };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await optimizeWeb();
}
