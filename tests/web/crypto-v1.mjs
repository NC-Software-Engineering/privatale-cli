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
// P1 synthetic pointer-free adapter, separate from v0. No persistence or sync apply.
const U64 = (1n << 64n) - 1n;
const MAX_BODY = 5000000000n;
function bytes(v, n, max = n) {
  if (!(v instanceof Uint8Array) || !(v.buffer instanceof ArrayBuffer) || v.byteLength < n || v.byteLength > max)
    throw new TypeError('InvalidBytes');
  return v.slice(); // reject SharedArrayBuffer; own a stable copy
}
function uint(v, max = 0xffffffff) {
  if (typeof v !== 'number' || !Number.isInteger(v) || v < 0 || v > max) throw new TypeError('InvalidInteger');
  return v;
}
function big(v, max = U64) {
  if (typeof v !== 'bigint' || v < 0n || v > max) throw new TypeError('InvalidBigInt');
  return v;
}
function le(v, n) { const b = new Uint8Array(n); for (let i=0;i<n;i++) {b[i]=Number(v & 255n);v >>= 8n;}return b; }
function cat(...parts) {const b=new Uint8Array(parts.reduce((n,p)=>n+p.length,0));let i=0;for(const p of parts){b.set(p,i);i+=p.length;}return b;}
function version(c) {if(uint(c.format_version)!==1)throw new TypeError('InvalidVersion');return le(1n,4);}
function sync(c) {
  const kind=uint(c.kind,5);if(kind===0)throw new TypeError('InvalidKind');
  const present=c.covers_up_to_seq!==null;
  if(present!==(kind===2))throw new TypeError('InvalidCoverage');
  const v=uint(c.key_version);if(v===0)throw new TypeError('InvalidVersion');
  return cat(bytes(c.owner_id,16),bytes(c.doc_id,16),bytes(c.item_id,16),le(BigInt(v),4),version(c),new Uint8Array([kind]),le(big(c.epoch),8),bytes(c.device_id,16),new Uint8Array([Number(present)]),le(present?big(c.covers_up_to_seq,(1n<<63n)-1n):0n,8));
}
function amk(c) {const v=uint(c.amk_version);if(!v)throw new TypeError('InvalidVersion');return cat(bytes(c.owner_id,16),bytes(c.envelope_id,16),le(BigInt(v),4),version(c));}
function blob(c) {
  if(c.class===1)return cat(bytes(c.owner_id,16),bytes(c.doc_id,16),bytes(c.blob_id,16),version(c));
  if(c.class===2)return cat(sync(c),bytes(c.blob_id,16));
  throw new TypeError('InvalidClass');
}
function entropy(n) {
  const b=new Uint8Array(n);
  try {
    if(!globalThis.isSecureContext || typeof globalThis.crypto?.getRandomValues!=='function')throw new Error();
    globalThis.crypto.getRandomValues(b);return b;
  } catch {b.fill(0);throw new Error('EntropyUnavailable');}
}
function password(p) {const b=bytes(p,1,1024);new TextDecoder('utf-8',{fatal:true}).decode(b);return b;}
export async function createBrowserCryptoV1(wasm) {
  const {instance}=await WebAssembly.instantiate(wasm,{});const e=instance.exports;
  for(const name of ['v1_abort','v1_clear','v1_push','v1_run','v1_len','v1_byte'])if(typeof e[name]!=='function')throw new Error('InvalidABI');
  let generation=0,active=false;
  const abort=()=>{generation++;active=false;e.v1_abort();};
  function guard(fn) {try{return fn();}catch(error){abort();throw error;}}
  function call(op,fields,arg=0n) {
    e.v1_clear();
    try {
      for(let i=0;i<5;i++)for(const v of fields[i]??[])if(e.v1_push(i,v)!==1)throw new Error('CryptoRejected');
      if(e.v1_run(op,arg)!==1)throw new Error('CryptoRejected');
      const n=e.v1_len();if(n>1048576)throw new Error('InvalidABI');
      const out=new Uint8Array(n);for(let i=0;i<n;i++){const v=e.v1_byte(i);if(v>255)throw new Error('InvalidABI');out[i]=v;}return out;
    } finally {e.v1_clear();for(const b of fields)if(b instanceof Uint8Array)b.fill(0);}
  }
  const idle=()=>{if(active)throw new Error('StreamActive');};
  function inline(op,key,c,data) {return guard(()=>{idle();const f=[bytes(key,32),sync(c),null,bytes(data,0,op===1?1032180:1048576)];if(op===1)f[4]=entropy(24);return call(op,f);});}
  function device(op,key,c,device,pk,data) {return guard(()=>{idle();const f=[op===4?bytes(key,32):null,amk(c),op===3?cat(bytes(device,16),bytes(pk,32)):bytes(device,16),bytes(data,op===3?32:308)];if(op===3)f[4]=entropy(32);return call(op,f);});}
  function recovery(op,key,c,data) {return guard(()=>{idle();const f=[bytes(key,32),amk(c),null,bytes(data,op===5?32:300)];if(op===5)f[4]=entropy(24);return call(op,f);});}
  function pass(op,p,c,data,upgrade=false) {return guard(()=>{idle();if(typeof upgrade!=='boolean')throw new TypeError('InvalidUpgrade');const f=[password(p),amk(c),null,bytes(data,op===7?32:328)];if(op===7)f[4]=entropy(40);return call(op,f,upgrade?4n:3n);});}
  function stream(encode,key,c,lengthOrHeader) {return guard(()=>{idle();const f=[bytes(key,32),blob(c),null,null];let length=0n;if(encode){length=big(lengthOrHeader,MAX_BODY);f[4]=entropy(32);}else{f[3]=bytes(lengthOrHeader,45);}const header=call(encode?9:12,f,length);active=true;const token=++generation;let index=0n;
    const check=()=>{if(!active||token!==generation)throw new Error('StreamClosed');};
    return Object.freeze({get header(){return header.slice();},
      // Each call accepts/returns <= one 64 KiB record. No whole-file buffer.
      authenticatedPrefix: encode?undefined:record=>guard(()=>{check();return call(13,[null,null,null,bytes(record,40,65576)]);}),
      next: !encode?undefined:body=>guard(()=>{check();const b=bytes(body,0,65536);const start=index*65536n;const p=length+12n;const want=Number((p<start+65536n?p:start+65536n)-(start<12n?12n:start));if(b.length!==Math.max(0,want))throw new TypeError('InvalidChunkLength');const out=call(10,[null,null,null,b,entropy(24)]);index++;return out;}),
      finish:()=>guard(()=>{check();call(encode?11:14,[]);active=false;generation++;}),
      abort,
    });
  });}
  return Object.freeze({
    seal:(k,c,b)=>inline(1,k,c,b),open:(k,c,b)=>inline(2,k,c,b),
    deviceSeal:(c,d,pk,amkBytes)=>device(3,null,c,d,pk,amkBytes),deviceOpen:(sk,c,d,e)=>device(4,sk,c,d,null,e),
    recoverySeal:(k,c,a)=>recovery(5,k,c,a),recoveryOpen:(k,c,e)=>recovery(6,k,c,e),
    passwordSeal:(p,c,a,upgrade=false)=>pass(7,p,c,a,upgrade),passwordOpen:(p,c,e)=>pass(8,p,c,e),
    encoder:(k,c,n)=>stream(true,k,c,n),reader:(k,c,h)=>stream(false,k,c,h),abort,
  });
}
