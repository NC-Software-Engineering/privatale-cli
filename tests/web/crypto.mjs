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
// Temporary synthetic P1 bridge: intentionally byte-at-a-time, not a product ABI.
import { generateNonce } from './nonce.mjs';
const MAX_PAYLOAD = 1024 * 1024;
const MAX_ENVELOPE = 1081388;

function bytes(value, length, max = length) {
  if (!(value instanceof Uint8Array) || !(value.buffer instanceof ArrayBuffer)
      || value.length < length || value.length > max) throw new Error('InvalidInput');
  return value;
}
function u32(value) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) throw new Error('InvalidInput');
  return value;
}

export async function createBrowserCrypto(wasmBytes) {
  const module = await WebAssembly.compile(wasmBytes);
  if (WebAssembly.Module.imports(module).length !== 0) throw new Error('UnexpectedImports');
  const { exports: bridge } = await WebAssembly.instantiate(module, {});
  for (const name of ['bridge_reset', 'bridge_push', 'bridge_run', 'bridge_len', 'bridge_byte']) {
    if (typeof bridge[name] !== 'function') throw new Error('InvalidBridge');
  }
  function transform(operation, key, context, data) {
    bytes(key, 32);
    const { owner_id, doc_id, item_id, key_version, format_version } = context;
    bytes(owner_id, 1, 1024); bytes(doc_id, 16); bytes(item_id, 16);
    u32(key_version);
    if (format_version !== 0) throw new Error('InvalidInput');
    bytes(data, operation === 1 ? 0 : 300, operation === 1 ? MAX_PAYLOAD : MAX_ENVELOPE);
    // Entropy failure occurs before copying key/plaintext into a request or calling WASM.
    const nonce = operation === 1 ? generateNonce() : new Uint8Array(24);
    const request = new Uint8Array(100 + owner_id.length + data.length);
    let output;
    try {
      request.set(key); request.set(nonce, 32);
      request.set(doc_id, 56); request.set(item_id, 72);
      const view = new DataView(request.buffer);
      view.setUint32(88, key_version, true);
      view.setUint32(92, format_version, true);
      view.setUint32(96, owner_id.length, true);
      request.set(owner_id, 100); request.set(data, 100 + owner_id.length);
      bridge.bridge_reset();
      for (const byte of request) {
        if (bridge.bridge_push(byte) !== 0) throw new Error('BridgeRejected');
      }
      if (bridge.bridge_run(operation) !== 0) throw new Error('CryptoRejected');
      const length = bridge.bridge_len();
      if (length > (operation === 1 ? MAX_ENVELOPE : MAX_PAYLOAD)) throw new Error('InvalidBridgeOutput');
      output = new Uint8Array(length);
      for (let i = 0; i < length; i++) {
        const byte = bridge.bridge_byte(i);
        if (byte > 255) throw new Error('InvalidBridgeOutput');
        output[i] = byte;
      }
      return output;
    } catch (error) {
      output?.fill(0);
      throw error;
    } finally {
      request.fill(0);
      bridge.bridge_reset(); // drops/zeroizes Rust input and output, including open plaintext.
    }
  }
  // Instance is private. No nonce argument, injected RNG or shared transaction access.
  return Object.freeze({
    seal: (key, context, payload) => transform(1, key, context, payload),
    open: (key, context, envelope) => transform(2, key, context, envelope),
  });
}
