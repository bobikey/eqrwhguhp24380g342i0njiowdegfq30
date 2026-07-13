/**
 * Client-side loader for the native-emulation crypt5 decryptor.
 *
 * Loads the prebuilt unicorn.js (Unicorn 2.1.4, AArch64) CPU emulator + its
 * wrapper, the extracted `liberror-code.so`, and the marker→key table, then
 * runs the native decrypt routine fully in-browser (no server). See
 * ANALYSIS/FINDINGS.md for how this was reverse-engineered.
 *
 * Assets are served from /public/emu/ and /public/data/ and fetched once.
 */
import { createDecryptor } from './emu_core.js';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const customRequire = createRequire(import.meta.url);

let _decryptorPromise = null;

// Evaluate a UMD/CommonJS bundle's text and return its module.exports.
function evalCjs(src) {
  const shim = { exports: {} };
  // eslint-disable-next-line no-new-func
  new Function('module', 'exports', 'require', '__dirname', '__filename', src)(shim, shim.exports, customRequire, __dirname, __filename);
  return shim.exports.default || shim.exports;
}

async function buildDecryptor() {
  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const publicDir = path.resolve(__dirname, '../../public');
  
  const [unicornSrc, wrapperSrc, soBuf, keytableTxt] = await Promise.all([
    fs.readFile(path.join(publicDir, 'emu/unicorn_aarch64.js'), 'utf-8'),
    fs.readFile(path.join(publicDir, 'emu/unicorn-wrapper.js'), 'utf-8'),
    fs.readFile(path.join(publicDir, 'emu/liberror-code.so')),
    fs.readFile(path.join(publicDir, 'data/keytable.json'), 'utf-8'),
  ]);
  const keytable = JSON.parse(keytableTxt);
  const MUnicorn = evalCjs(unicornSrc);
  return createDecryptor({
    MUnicorn,
    wrapperSrc,
    soBytes: new Uint8Array(soBuf),
    keytable,
    verbose: 0,
  });
}

/** Returns a cached `{ decrypt(inBytes: Uint8Array) -> Uint8Array }`. */
export function getNativeDecryptor() {
  if (!_decryptorPromise) _decryptorPromise = buildDecryptor();
  return _decryptorPromise;
}
