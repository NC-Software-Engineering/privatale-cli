// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 NC Software Engineering
//
// This file is part of privatale-cli.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
import { runP1Browser } from './check-v1.mjs';
import { generateNonce } from './nonce.mjs';
import { createBrowserCrypto } from './crypto.mjs';

function check(condition, message) {
  if (!condition) throw new Error(message);
}
async function bytes(url) {
  const response = await fetch(url);
  check(response.ok, `Fetch failed: ${url}`);
  return response.arrayBuffer();
}

async function run() {
  check(globalThis.isSecureContext, 'Secure context required');
  const api = await createBrowserCrypto(await bytes('/bridge.wasm'));
  const key = new Uint8Array(32).fill(7);
  const context = { owner_id: new Uint8Array([1, 0, 2]), doc_id: new Uint8Array(16).fill(3),
    item_id: new Uint8Array(16).fill(4), key_version: 1, format_version: 0 };
  const seen = new Set();
  for (let i = 0; i < 32; i++) {
    const nonce = generateNonce();
    check(nonce instanceof Uint8Array && nonce.length === 24, 'Invalid nonce shape');
    const encoded = Array.from(nonce, b => b.toString(16).padStart(2, '0')).join('');
    check(!seen.has(encoded), 'Duplicate in synthetic smoke sample');
    seen.add(encoded);
  }
  // Failure injection is only in the test harness; restore native Crypto afterwards.
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  let failureCases = 0;
  try {
    for (const mode of ['missing', 'throw', 'partial']) {
      let captured;
      const fake = mode === 'missing' ? undefined : { getRandomValues(target) {
        captured = target;
        if (mode === 'partial') target.fill(42, 0, 12);
        throw new Error('Synthetic entropy failure');
      } };
      Object.defineProperty(globalThis, 'crypto', { configurable: true, value: fake });
      let rejected = false;
      try { generateNonce(); } catch (error) { rejected = error.message === 'EntropyUnavailable'; }
      check(rejected, `Must reject ${mode}`);
      let sealRejected = false;
      try { api.seal(key, context, new Uint8Array([1])); }
      catch (error) { sealRejected = error.message === 'EntropyUnavailable'; }
      check(sealRejected, `WASM seal must reject entropy ${mode}`);
      if (captured) check(captured.every(byte => byte === 0), 'Partial buffer not cleared');
      failureCases++;
    }
  } finally {
    if (descriptor) Object.defineProperty(globalThis, 'crypto', descriptor);
    else delete globalThis.crypto;
  }
  check(generateNonce().length === 24, 'Native crypto not restored');

  let bridgeRoundtrips = 0;
  const envelopeNonces = new Set();
  for (const length of [0, 245, 1024 * 1024]) {
    const payload = new Uint8Array(length).fill(0x80);
    const sealed = api.seal(key, context, payload);
    const opened = api.open(key, context, sealed);
    check(opened.length === length && opened.every(b => b === 0x80), 'Bridge roundtrip');
    const nonce = Array.from(sealed.slice(4, 28)).join(',');
    check(!envelopeNonces.has(nonce), 'Duplicate bridge nonce sample');
    envelopeNonces.add(nonce);
    bridgeRoundtrips++;
  }
  const sealed = api.seal(key, context, new Uint8Array([0, 255]));
  let bridgeRefusals = 0;
  const badEnvelope = sealed.slice(); badEnvelope[badEnvelope.length - 1] ^= 1;
  for (const args of [
    [new Uint8Array(32).fill(8), context, sealed],
    [key, { ...context, owner_id: new Uint8Array([9]) }, sealed],
    [key, context, badEnvelope],
  ]) {
    let rejected = false;
    try { api.open(...args); } catch (error) { rejected = error.message === 'CryptoRejected'; }
    check(rejected, 'Bridge authentication refusal'); bridgeRefusals++;
  }
  check(api.open(key, context, sealed)[1] === 255, 'Bridge recovery after refusal');

  const padmeModule = await WebAssembly.compile(await bytes('/core.wasm'));
  check(WebAssembly.Module.imports(padmeModule).length === 0, 'Unexpected core imports');
  const padme = await WebAssembly.instantiate(padmeModule, {});
  const csvResponse = await fetch('/padme.csv');
  check(csvResponse.ok, 'Missing Padme vectors');
  const rows = (await csvResponse.text()).trim().split('\n').slice(1);
  check(rows.length === 24, 'Unexpected Padme vector count');
  for (const row of rows) {
    const [input, expected] = row.split(',');
    const actual = BigInt.asUintN(64, padme.exports.prototype_padme_len(BigInt(input)));
    check(actual === (expected === 'overflow' ? 0n : BigInt(expected)), `Padme: ${row}`);
  }
  const module = await WebAssembly.compile(await bytes('/vectors.wasm'));
  check(WebAssembly.Module.imports(module).length === 0, 'Unexpected harness imports');
  const exports = [
    'exact_bytes_and_binary_roundtrip', 'independent_length_vectors_include_header',
    'all_truncations_and_extra_bytes_are_rejected',
    'unknown_header_and_each_nonzero_padding_byte_are_rejected',
    'forged_lengths_and_resource_limits_are_rejected', 'framing_is_not_authentication',
    'envelope_vectors', 'key_vectors', 'sync_item_v1_vectors', 'amk_v1_vectors', 'blob_v1_vectors',
  ];
  for (const name of exports) {
    const instance = await WebAssembly.instantiate(module, {});
    check(typeof instance.exports[name] === 'function', `Missing export: ${name}`);
    instance.exports[name](); // Rust assertion failure becomes a trap.
  }
  const p1 = await runP1Browser(await bytes('/bridge-v1.wasm'));
  check(p1.status === 'PASS', 'P1 adapter checks failed');
  return { p1, amkSharedTests: 4, blobSharedTests: 4, status: 'PASS', secureContext: globalThis.isSecureContext,
    browser: navigator.userAgent, nonceSamples: 32, entropyFailureCases: failureCases,
    padmeVectors: rows.length, framingTests: 6, envelopeTests: 5, hkdfTests: 3, syncItemV1Tests: 4,
    bridgeRoundtrips, bridgeRefusals, bridgeEntropyRefusals: failureCases,
    limitation: 'Synthetic temporary browser/WASM seal binding; no storage or product key management.' };
}

try {
  globalThis.prototypeResult = await run();
} catch (error) {
  globalThis.prototypeResult = { status: 'FAIL', error: String(error) };
}
document.querySelector('#result').textContent = JSON.stringify(globalThis.prototypeResult, null, 2);
