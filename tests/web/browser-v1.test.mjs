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
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {webcrypto} from 'node:crypto';
import {runP1Browser} from './check-v1.mjs';
import {createBrowserCryptoV1} from './crypto-v1.mjs';
Object.defineProperty(globalThis,'crypto',{configurable:true,value:webcrypto});
globalThis.isSecureContext=true;
const wasm=await readFile(new URL('../../target/wasm32-unknown-unknown/debug/examples/browser_v1.wasm',import.meta.url));
test('P1 v1 adapter: real WASM, bounded streams, types, entropy, poison',()=>{
 return runP1Browser(wasm).then(result=>{assert.equal(result.status,'PASS');assert.equal(result.deviceChecks,2);assert.equal(result.entropyFailures,15);assert.equal(result.argon.length,2);console.log(JSON.stringify({nodeNotBrowser:true,...result}));});
});
test('pointer-free ABI clears output and invalidates stream after every refusal',async()=>{
 const {instance:{exports:e}}=await WebAssembly.instantiate(wasm,{});
 assert.equal(e.v1_len(),0);assert.equal(e.v1_byte(0),256);
 assert.equal(e.v1_push(3,256),0);assert.equal(e.v1_len(),0);
 assert.equal(e.v1_run(999,0n),0);assert.equal(e.v1_byte(0),256);
 assert.equal(e.v1_push(99,1),0);assert.equal(e.v1_byte(0),256);
 const api=await createBrowserCryptoV1(wasm);const k=new Uint8Array(32);
 const c={class:1,owner_id:new Uint8Array(16),doc_id:new Uint8Array(16),blob_id:new Uint8Array(16),format_version:1};
 const enc=api.encoder(k,c,0n);assert.throws(()=>api.encoder(k,c,0n));assert.throws(()=>enc.next(new Uint8Array()));
});
