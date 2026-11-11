# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 NC Software Engineering
#
# This file is part of privatale-cli.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
"""Verify frozen full AMK vectors, official HPKE Base vector and Argon2 KAT."""
from p1_oracle import *
if not __debug__: raise RuntimeError("Assertions must be enabled")
from pathlib import Path
import json, sys
ROOT=Path(__file__).resolve().parents[2]
def generate():
    context=bytes(range(16))+bytes(range(16,32))+u32(0x01020304)+u32(1)
    amk=bytes(range(32)); frame=b'PTA1'+amk+bytes(220)
    rows=[['kind','t','secret','coins','context','extra','amk','info','key','aad','frame','envelope']]
    for kind,t in [('device',0),('recovery',0),('password',3),('password',4)]:
        domain=lambda n: ('privatale/amk/'+kind+'/'+n+'/v1\0').encode()+context
        secret=bytes(range(32,64)) if kind!='password' else 'P1 synthetic päss'.encode()
        if kind=='device':
            pk=public(secret); device=bytes(range(64,80)); extra=device+pk; coins=bytes(range(96,128))
            info=domain('hpke')+extra
            enc,_,_,_=hpke(coins,pk,info,b'',b'')
            header=b'PTK1'+enc; aad=domain('aad')+extra+header
            _,key,_,ct=hpke(coins,pk,info,aad,frame)
        else:
            extra=b''; nonce=bytes([t+1])*24
            coins=nonce if kind=='recovery' else bytes(range(16))+nonce
            info=domain('key')
            raw=secret if kind=='recovery' else argon(secret,coins[:16],t)
            key=hkdf(raw,info)
            header=b'PTR1'+nonce if kind=='recovery' else b'PTW1'+coins[:16]+u32(65536)+u32(t)+u32(1)+nonce
            aad=domain('aad')+header;ct=xseal(key,nonce,aad,frame)
        rows.append([kind,t,secret,coins,context,extra,amk,info,key,aad,frame,header+ct])
    return csv(rows)
def official():
    v=json.loads((ROOT/'test-vectors/hpke-rfc9180.json').read_text()); b=lambda k:bytes.fromhex(v[k]); e=v['encryptions'][0]
    enc,key,nonce,ct=hpke(b('ikmE'),b('pkRm'),b('info'),bytes.fromhex(e['aad']),bytes.fromhex(e['pt']))
    assert enc==b('enc') and key==b('key') and nonce==b('base_nonce') and ct==bytes.fromhex(e['ct'])
    return csv([['ikm','pk','sk','info','aad','pt','enc','ct'],[b('ikmE'),b('pkRm'),b('skRm'),b('info'),bytes.fromhex(e['aad']),bytes.fromhex(e['pt']),enc,ct]])
# RFC9106 section 5.3 uses secret/AD, which wrappers intentionally disallow.
# Published argon2 reference CLI KAT: password/somesalt, id v19 m65536 t2 p1.
KAT='09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7'
def main():
    if sys.argv[1:] not in ([],['--emit']): raise SystemExit('usage: check_amk_vectors.py [--emit]')
    from argon_rfc9106 import check
    check()
    # Frozen independently evaluated no-secret/AD Argon2 known answer.
    assert argon(b'password',b'somesalt',2).hex()==KAT
    full=generate(); off=official()
    if sys.argv[1:]: print(full,end=''); return
    assert (ROOT/'test-vectors/amk-v1.csv').read_text()==full, 'AMK vector mismatch'
    assert (ROOT/'test-vectors/hpke-official.csv').read_text()==off, 'official vector mismatch'
    print('PASS: full device/recovery/password t3/t4 vectors; official HPKE and Argon2 KAT')
if __name__=='__main__':main()
