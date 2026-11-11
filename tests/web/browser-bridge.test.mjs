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
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { webcrypto } from 'node:crypto';
import { createContext, SourceTextModule } from 'node:vm';

const wasm = await readFile(new URL('../../target/wasm32-unknown-unknown/debug/examples/browser_bridge.wasm', import.meta.url));
const nonceSource = await readFile(new URL('./nonce.mjs', import.meta.url), 'utf8');
const source = await readFile(new URL('./crypto.mjs', import.meta.url), 'utf8');
async function client(crypto = webcrypto) {
  const context = createContext({ crypto, isSecureContext: true, Uint8Array, ArrayBuffer, DataView, WebAssembly });
  const nonce = new SourceTextModule(nonceSource, { context });
  await nonce.link(() => { throw new Error('Unexpected import'); });
  const module = new SourceTextModule(source, { context });
  await module.link(name => { assert.equal(name, './nonce.mjs'); return nonce; });
  await module.evaluate();
  return module.namespace.createBrowserCrypto(wasm);
}
const context = () => ({ owner_id: new Uint8Array([1, 0, 2]), doc_id: new Uint8Array(16).fill(3),
  item_id: new Uint8Array(16).fill(4), key_version: 0x01020304, format_version: 0 });
const hex = text => Uint8Array.from(Buffer.from(text, 'hex'));

test('full independent PTE0 fixtures through JS/WASM seal/open', async () => {
  const rows = (await readFile(new URL('../../test-vectors/pte0.csv', import.meta.url), 'utf8')).trim().split('\n').slice(1);
  assert.equal(rows.length, 2);
  for (const row of rows) {
    const [key, nonce, owner, doc, item, version, payload, , , envelope] = row.split(',');
    const api = await client({ getRandomValues(target) { target.set(hex(nonce)); return target; } });
    const ctx = { owner_id: hex(owner), doc_id: hex(doc), item_id: hex(item), key_version: Number(version), format_version: 0 };
    assert.deepEqual(api.seal(hex(key), ctx, hex(payload)), hex(envelope));
    assert.deepEqual(api.open(hex(key), ctx, hex(envelope)), hex(payload));
  }
});

test('real host Web Crypto, fresh nonce, binary/empty/maximum roundtrip', async () => {
  const api = await client();
  const key = new Uint8Array(32).fill(7);
  const ctx = context();
  const seen = new Set();
  for (const length of [0, 245, 1024 * 1024]) {
    const payload = new Uint8Array(length).fill(0x80);
    const sealed = api.seal(key, ctx, payload);
    assert.deepEqual(api.open(key, ctx, sealed), payload);
    const nonce = Buffer.from(sealed.slice(4, 28)).toString('hex');
    assert(!seen.has(nonce)); seen.add(nonce);
    assert(payload.every(b => b === 0x80));
  }
  assert(key.every(b => b === 7));
});

test('wrong key, all AAD components and modified ciphertext refuse; later request recovers', async () => {
  const api = await client();
  const key = new Uint8Array(32).fill(7);
  const ctx = context();
  const payload = new Uint8Array([0, 255, 4]);
  const sealed = api.seal(key, ctx, payload);
  assert.throws(() => api.open(new Uint8Array(32).fill(8), ctx, sealed), /CryptoRejected/);
  for (const field of ['owner_id', 'doc_id', 'item_id', 'key_version', 'format_version']) {
    const other = context();
    if (typeof other[field] === 'number') other[field]++;
    else other[field][0] ^= 1;
    assert.throws(() => api.open(key, other, sealed));
  }
  for (const offset of [0, 4, 28, sealed.length - 1]) {
    const bad = sealed.slice(); bad[offset] ^= 1;
    assert.throws(() => api.open(key, ctx, bad), /CryptoRejected/);
  }
  assert.throws(() => api.open(key, ctx, sealed.slice(0, -1)));
  assert.throws(() => api.seal(new Uint8Array(31), ctx, payload), /InvalidInput/);
  assert.throws(() => api.seal(key, ctx, new Uint8Array(1024 * 1024 + 1)), /InvalidInput/);
  assert.deepEqual(api.open(key, ctx, sealed), payload);
});

test('entropy failure prevents seal; open does not need entropy', async () => {
  const good = await client();
  const key = new Uint8Array(32).fill(7); const ctx = context();
  const sealed = good.seal(key, ctx, new Uint8Array([1]));
  for (const crypto of [undefined, { getRandomValues(target) { target.fill(9, 0, 12); throw new Error('failure'); } }]) {
    // undefined default parameter would select webcrypto; null exercises absent crypto instead.
    const api = await client(crypto ?? null);
    assert.throws(() => api.seal(key, ctx, new Uint8Array([1])), /EntropyUnavailable/);
    assert.deepEqual(api.open(key, ctx, sealed), new Uint8Array([1]));
  }
});

test('raw WASM malformed transaction has no stale output and resets', async () => {
  const { instance: { exports: api } } = await WebAssembly.instantiate(wasm, {});
  assert.equal(api.bridge_run(1), 1);
  assert.equal(api.bridge_len(), 0);
  assert.equal(api.bridge_byte(0xffffffff), 256);
  api.bridge_reset();
  assert.equal(api.bridge_push(256), 1);
  assert.equal(api.bridge_push(1), 1);
  assert.equal(api.bridge_run(1), 1);
  api.bridge_reset();
  assert.equal(api.bridge_push(1), 0);
  assert.equal(api.bridge_run(99), 1);
  assert.equal(api.bridge_len(), 0);
});
