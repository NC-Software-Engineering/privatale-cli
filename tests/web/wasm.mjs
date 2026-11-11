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
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const root = new URL('../../', import.meta.url);
const bytes = await readFile(new URL('target/wasm32-unknown-unknown/debug/privatale_core.wasm', root));
const { instance } = await WebAssembly.instantiate(bytes, {});
const native = fileURLToPath(new URL('target/debug/privatale-prototype', root));
const lines = (await readFile(new URL('test-vectors/padme.csv', root), 'utf8')).trim().split('\n').slice(1);
for (const line of lines) {
  const [input, expected] = line.split(',');
  // WebAssembly i64 се връща като signed BigInt; възстановяваме u64.
  const actual = BigInt.asUintN(64, instance.exports.prototype_padme_len(BigInt(input)));
  assert.equal(actual, expected === 'overflow' ? 0n : BigInt(expected), line);
  if (expected === 'overflow') {
    assert.throws(() => execFileSync(native, ['padme-length', input], { stdio: 'pipe' }), error => error.status === 2);
  } else {
    assert.equal(execFileSync(native, ['padme-length', input], { encoding: 'utf8' }).trim(), expected, line);
  }
}
console.log(`PASS: ${lines.length} споделени вектора в Linux CLI и реален WASM (Node).`);

const framingBytes = await readFile(new URL('target/wasm32-unknown-unknown/debug/examples/framing_vectors.wasm', root));
const framingModule = await WebAssembly.compile(framingBytes);
assert.deepEqual(WebAssembly.Module.imports(framingModule), [], 'Harness-ът не изисква host imports.');
const framingCases = [
  'exact_bytes_and_binary_roundtrip',
  'independent_length_vectors_include_header',
  'all_truncations_and_extra_bytes_are_rejected',
  'unknown_header_and_each_nonzero_padding_byte_are_rejected',
  'forged_lengths_and_resource_limits_are_rejected',
  'framing_is_not_authentication',
];
for (const name of framingCases) {
  // Отделен instance: всеки тест започва с чиста WASM памет.
  const framing = await WebAssembly.instantiate(framingModule, {});
  assert.equal(typeof framing.exports[name], 'function', `Липсва тест: ${name}`);
  assert.doesNotThrow(() => framing.exports[name](), `WASM framing: ${name}`);
}
console.log(`PASS: ${framingCases.length} общи Rust framing теста, реално изпълнени във WASM (Node).`);
const crypto = await WebAssembly.instantiate(framingModule, {});
assert.equal(typeof crypto.exports.envelope_vectors, 'function');
assert.doesNotThrow(() => crypto.exports.envelope_vectors(), 'WASM: XChaCha20-Poly1305, AAD и envelope тестове');
console.log('PASS: 5 общи криптографски теста във WASM, включително публикуван XChaCha20-Poly1305 вектор и 2 независими пълни PTE0 вектора.');
const keys = await WebAssembly.instantiate(framingModule, {});
assert.equal(typeof keys.exports.key_vectors, 'function');
assert.doesNotThrow(() => keys.exports.key_vectors(), 'WASM: RFC 5869, HKDF fixtures и key isolation');
console.log('PASS: 3 общи HKDF теста във WASM, включително RFC 5869 и 5 независими prototype вектора.');
const v1 = await WebAssembly.instantiate(framingModule, {});
assert.equal(typeof v1.exports.sync_item_v1_vectors, 'function');
assert.doesNotThrow(() => v1.exports.sync_item_v1_vectors(), 'WASM sync-item v1');
console.log('PASS: 4 sync-item v1 WASM теста, включително 5 независими пълни вектора.');

for (const name of ['amk_v1_vectors', 'blob_v1_vectors']) {
  const test = await WebAssembly.instantiate(framingModule, {});
  const start = performance.now();
  assert.equal(typeof test.exports[name], 'function');
  test.exports[name]();
  console.log(`PASS: shared ${name} WASM ${(performance.now()-start).toFixed(1)} ms`);
}
for (const t of [3, 4]) {
  const {exports:e} = await WebAssembly.instantiate(framingModule, {});
  const before=e.memory.buffer.byteLength;
  const start=performance.now();e.argon_profile_cost(t);const ms=performance.now()-start;
  const after=e.memory.buffer.byteLength;
  assert.ok(after-before>=67108864, 'fresh WASM instance must allocate full approved 64 MiB arena');
  console.log(`Argon2id WASM m=65536KiB t=${t} p=1 arena=67108864 time_ms=${ms.toFixed(1)} linear_before=${before} linear_after=${after}`);
}
