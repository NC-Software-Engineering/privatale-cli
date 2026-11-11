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
import { createBrowserCryptoV1 } from './crypto-v1.mjs';
const check=(v,m)=>{if(!v)throw new Error(m);};
const same=(a,b)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
const rejects=fn=>{let bad=false;try{fn();}catch{bad=true;}check(bad,'Expected refusal');};
const hex=s=>new Uint8Array(s.match(/../g).map(v=>parseInt(v,16)));
export async function runP1Browser(wasm) {
 const api=await createBrowserCryptoV1(wasm);
 const key=new Uint8Array(32).fill(7), body=new Uint8Array([0,255,5]);
 const c={owner_id:new Uint8Array(16).fill(1),doc_id:new Uint8Array(16).fill(2),item_id:new Uint8Array(16).fill(3),device_id:new Uint8Array(16).fill(4),key_version:1,format_version:1,kind:2,epoch:0xffffffffffffffffn,covers_up_to_seq:0n};
 const sealed=api.seal(key,c,body);check(same(api.open(key,c,sealed),body),'Inline v1 roundtrip');
 for(const change of [{epoch:1},{epoch:'1'},{epoch:-1n},{epoch:1n<<64n},{covers_up_to_seq:1n<<63n},{covers_up_to_seq:null},{key_version:0},{key_version:4294967296},{key_version:1n},{format_version:0},{kind:6},{device_id:new Uint8Array(15)}])rejects(()=>api.open(key,{...c,...change},sealed));
 for(const bad of [new Uint8Array(31),[7],new Uint16Array(32)])rejects(()=>api.open(bad,c,sealed));
 if(typeof SharedArrayBuffer==='function')rejects(()=>api.seal(new Uint8Array(new SharedArrayBuffer(32)),c,body));
 rejects(()=>api.seal(key,c,new Uint8Array(1032181)));
 const corrupt=sealed.slice();corrupt[corrupt.length-1]^=1;rejects(()=>api.open(key,c,corrupt));check(same(api.open(key,c,sealed),body),'No stale inline plaintext');
 const ac={owner_id:c.owner_id,envelope_id:new Uint8Array(16).fill(9),amk_version:1,format_version:1};
 const recovery=api.recoverySeal(key,ac,key);check(same(api.recoveryOpen(key,ac,recovery),key),'Recovery roundtrip');
 // Public synthetic recipient independently derived with OpenSSL X25519.
 const sk=new Uint8Array(32).fill(3);
 const pk=hex('5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22');
 const device=new Uint8Array(16).fill(4);
 const d=api.deviceSeal(ac,device,pk,key);check(same(api.deviceOpen(sk,ac,device,d),key),'Device roundtrip');const badDevice=d.slice();badDevice[4]^=1;rejects(()=>api.deviceOpen(sk,ac,device,badDevice));const deviceChecks=2;
 const descriptor=Object.getOwnPropertyDescriptor(globalThis,'crypto');let entropyFailures=0;
 try {for(const mode of ['missing','throw','partial']){let captured;Object.defineProperty(globalThis,'crypto',{configurable:true,value:mode==='missing'?undefined:{getRandomValues(b){captured=b;if(mode==='partial')b.fill(42,0,4);throw new Error('synthetic');}}});for(const fn of [()=>api.seal(key,c,body),()=>api.recoverySeal(key,ac,key),()=>api.passwordSeal(body,ac,key),()=>api.deviceSeal(ac,device,key,key),()=>api.encoder(key,{class:1,...c,blob_id:c.item_id},0n)]){rejects(fn);if(captured)check(captured.every(v=>v===0),'Partial entropy buffer wiped');entropyFailures++;}}}finally{if(descriptor)Object.defineProperty(globalThis,'crypto',descriptor);else delete globalThis.crypto;}
 const password=new TextEncoder().encode('P1 synthetic password');const argon=[];
 for(const upgrade of [false,true]){const start=performance.now();const p=api.passwordSeal(password,ac,key,upgrade);const sealMs=performance.now()-start;check(same(api.passwordOpen(password,ac,p),key),'Password roundtrip');argon.push({mKiB:65536,t:upgrade?4:3,p:1,sealMs});const bad=p.slice();bad[20]=1;rejects(()=>api.passwordOpen(password,ac,bad));}
 rejects(()=>api.passwordSeal(new Uint8Array([255]),ac,key));
 for(const cls of [1,2]){
  const bc={...c,class:cls,blob_id:new Uint8Array(16).fill(8)};
  for(const length of [0n,245n,65524n,65525n,131061n]){
   const enc=api.encoder(key,bc,length);const header=enc.header;const records=[];let remaining=length,index=0;
   do{const capacity=index===0?65524:65536;const size=Number(remaining<BigInt(capacity)?remaining:BigInt(capacity));records.push(enc.next(new Uint8Array(size).fill(11)));remaining-=BigInt(size);index++;}while(remaining>0n);
   // Some whole-file Padme buckets require a final padding-only chunk.
   const view=new DataView(header.buffer,header.byteOffset);const p=view.getBigUint64(37,true);const count=Number((p+65535n)/65536n);
   while(records.length<count)records.push(enc.next(new Uint8Array()));enc.finish();rejects(()=>enc.finish());
   const reader=api.reader(key,bc,header);let total=0;for(const record of records){check(record.length<=65576,'Bounded record');const prefix=reader.authenticatedPrefix(record);check(prefix.length<=65536&&prefix.every(v=>v===11),'Authenticated bounded prefix');total+=prefix.length;}check(BigInt(total)===length,'Body length');reader.finish();rejects(()=>reader.finish());
   const incomplete=api.reader(key,bc,header);rejects(()=>incomplete.finish());rejects(()=>incomplete.authenticatedPrefix(records[0]));
   const broken=api.reader(key,bc,header);const bad=records[0].slice();bad[bad.length-1]^=1;rejects(()=>broken.authenticatedPrefix(bad));rejects(()=>broken.authenticatedPrefix(records[0]));rejects(()=>broken.finish());
  }
 }
 // Entropy failure after the header must permanently invalidate that encoder.
 const enc=api.encoder(key,{class:1,...c,blob_id:c.item_id},0n);
 try{Object.defineProperty(globalThis,'crypto',{configurable:true,value:{getRandomValues(b){b[0]=1;throw new Error('synthetic');}}});rejects(()=>enc.next(new Uint8Array()));}finally{if(descriptor)Object.defineProperty(globalThis,'crypto',descriptor);else delete globalThis.crypto;}
 rejects(()=>enc.next(new Uint8Array()));rejects(()=>enc.finish());
 rejects(()=>api.encoder(key,{class:1,...c,blob_id:c.item_id},5000000001n));rejects(()=>api.encoder(key,{class:1,...c,blob_id:c.item_id},5));
 return {status:'PASS',entropyFailures,deviceChecks,argon,streamClasses:2,streamSizes:5};
}
