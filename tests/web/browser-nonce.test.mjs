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
import { createContext, SourceTextModule } from 'node:vm';

const source = await readFile(new URL('./nonce.mjs', import.meta.url), 'utf8');
async function load(globals) {
  // Test-only realm injection; production module exposes no RNG injection API.
  const module = new SourceTextModule(source, { context: createContext(globals) });
  await module.link(() => { throw new Error('Unexpected module import'); });
  await module.evaluate();
  return module.namespace.generateNonce;
}

test('exact 24 bytes, correct receiver, fresh buffers, one call per nonce', async () => {
  let calls = 0;
  const crypto = { getRandomValues(target) {
    assert.equal(this, crypto);
    assert.equal(target.length, 24);
    for (let i = 0; i < 24; i++) target[i] = i + calls;
    calls++;
    return target;
  } };
  const generate = await load({ isSecureContext: true, crypto });
  const first = generate();
  const second = generate();
  assert.equal(calls, 2);
  assert.notEqual(first.buffer, second.buffer);
  assert.deepEqual([...first], Array.from({ length: 24 }, (_, i) => i));
  assert.deepEqual([...second], Array.from({ length: 24 }, (_, i) => i + 1));
});

test('missing crypto or method fails without fallback', async () => {
  for (const crypto of [undefined, null, {}, { getRandomValues: 1 }]) {
    const generate = await load({ isSecureContext: true, crypto });
    assert.throws(generate, { message: 'EntropyUnavailable' });
  }
});

test('insecure or unknown context never calls entropy', async () => {
  for (const isSecureContext of [false, undefined, 'true']) {
    let calls = 0;
    const generate = await load({ isSecureContext, crypto: { getRandomValues(target) {
      calls++;
      return target;
    } } });
    assert.throws(generate, { message: 'EntropyUnavailable' });
    assert.equal(calls, 0);
  }
});

test('full and partial entropy exceptions return nothing, wipe buffer, no retry', async () => {
  for (const partial of [false, true]) {
    let captured;
    let calls = 0;
    const generate = await load({ isSecureContext: true, crypto: { getRandomValues(target) {
      calls++;
      captured = target;
      if (partial) target.fill(42, 0, 12);
      throw new Error('synthetic host failure');
    } } });
    assert.throws(generate, { message: 'EntropyUnavailable' });
    assert.equal(calls, 1);
    assert.deepEqual([...captured], Array(24).fill(0));
  }
});

test('invalid return from host fails and clears target', async () => {
  let captured;
  const generate = await load({ isSecureContext: true, crypto: { getRandomValues(target) {
    captured = target;
    target.fill(42);
    return new Uint8Array(24);
  } } });
  assert.throws(generate, { message: 'EntropyUnavailable' });
  assert.deepEqual([...captured], Array(24).fill(0));
});
