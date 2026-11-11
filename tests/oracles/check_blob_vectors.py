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
"""Independent bounded-record encoder, frozen FULL bytes (not digests)."""
from p1_oracle import *
if not __debug__: raise RuntimeError("Assertions must be enabled")
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2]
def generate():
    rows=[['class','body_length','base','context','stream','body','key','header','aads','records']]
    for cls in [1,2]:
      for length in [0,244,245,65523,65524,65525,131061]:
        base=bytes(range(32)); stream=bytes([cls+length%251])*32
        context=bytes(range(16))+bytes(range(16,32))
        if cls==1: context+=bytes(range(32,48))+u32(1)
        else:
            context+=bytes(range(32,48))+u32(1)+u32(1)+b'\x02'+u64(0x0102030405060708)+bytes(range(48,64))+b'\x01'+u64(7)+bytes(range(64,80))
            base=hkdf(base,b'privatale/document-key/hkdf-sha256/v1\0'+bytes(range(16,32))+u32(1))
        body=bytes(i%251 for i in range(length))
        p=padded(12+length); header=b'PTB1'+bytes([cls])+stream+u64(p)
        key=hkdf(base,b'privatale/blob/key/v1\0'+bytes([cls])+context,stream)
        frame=(b'PTM1' if cls==1 else b'PTP1')+u64(length)+body+bytes(p-12-length)
        aads=[]; records=[]; count=(p+65535)//65536
        for index in range(count):
            chunk=frame[index*65536:(index+1)*65536];nonce=bytes([cls])+u64(length)+u64(index)+bytes(7)
            aad=b'privatale/blob/chunk/aad/v1\0'+context+header+u64(index)+bytes([index==count-1])+u32(len(chunk))
            aads.append(aad.hex()); records.append((nonce+xseal(key,nonce,aad,chunk)).hex())
        rows.append([cls,length,base,context,stream,body,key,header,';'.join(aads),';'.join(records)])
    return csv(rows)
if __name__=='__main__':
    if sys.argv[1:] not in ([],['--emit']):raise SystemExit('usage: check_blob_vectors.py [--emit]')
    full=generate()
    if sys.argv[1:]: print(full,end='')
    else:
        assert (ROOT/'test-vectors/blob-v1.csv').read_text()==full, 'blob vector mismatch'
        assert padded(12+5_000_000_000)==5_033_164_800
        assert 45+5_033_164_800+40*76800==5_036_236_845
        print('PASS: 14 independent full media/sync vectors, chunk and decimal cap arithmetic')
