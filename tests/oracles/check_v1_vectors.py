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
"""Independent approved sync-item v1 vectors; stdlib HKDF + libsodium AEAD.
Only synthetic public keys/data. Default verifies frozen CSV; --emit prints only.
"""
import ctypes as c
import ctypes.util
import hashlib
import hmac
from pathlib import Path
import sys


def generate():
    path = ctypes.util.find_library('sodium')
    if path is None:
        raise RuntimeError('libsodium unavailable')
    lib = c.CDLL(path)
    lib.sodium_init.argtypes = []
    lib.sodium_init.restype = c.c_int
    if lib.sodium_init() < 0:
        raise RuntimeError('sodium_init failed')
    encrypt = lib.crypto_aead_xchacha20poly1305_ietf_encrypt
    encrypt.argtypes = [c.c_void_p, c.POINTER(c.c_ulonglong), c.c_char_p, c.c_ulonglong,
                       c.c_char_p, c.c_ulonglong, c.c_void_p, c.c_char_p, c.c_char_p]
    encrypt.restype = c.c_int
    rows = ['amk,owner,doc,item,device,version,kind,epoch,coverage,nonce,body,info,key,aad,frame,envelope']
    for kind in range(1, 6):
        amk = bytes(range(32))
        owner = bytes.fromhex('00112233445546778899aabbccddeeff')
        doc = bytes.fromhex('10213243546546778899aabbccddeeff')
        item = bytes(range(16, 32))
        device = bytes(range(32, 48))
        version = 0x01020304
        epoch = 0x0102030405060708
        coverage = 0x0102030405060708 if kind == 2 else None
        nonce = bytes([kind]) * 24  # distinct nonces for this fixed synthetic AMK/doc.
        body = b'' if kind == 1 else bytes(range(245))
        info = b'privatale/document-key/hkdf-sha256/v1\0' + doc + version.to_bytes(4, 'little')
        prk = hmac.digest(b'', amk, hashlib.sha256)
        key = hmac.digest(prk, info + b'\x01', hashlib.sha256)
        header = b'PTI1' + nonce
        aad = (b'privatale/sync-item/aad/v1\0' + owner + doc + item
               + version.to_bytes(4, 'little') + (1).to_bytes(4, 'little')
               + bytes([kind]) + epoch.to_bytes(8, 'little') + device
               + bytes([coverage is not None]) + (coverage or 0).to_bytes(8, 'little') + header)
        raw = b'PTP1' + len(body).to_bytes(8, 'little') + body
        # Independent literal boundary cases, not Rust padded_len.
        size = 256 if kind == 1 else 272
        frame = raw + bytes(size - len(raw))
        output = c.create_string_buffer(len(frame) + 16)
        length = c.c_ulonglong()
        if encrypt(output, c.byref(length), frame, len(frame), aad, len(aad), None, nonce, key) != 0:
            raise RuntimeError('encrypt failed')
        if length.value != len(frame) + 16:
            raise RuntimeError('invalid output length')
        envelope = header + output.raw
        rows.append(','.join([amk.hex(), owner.hex(), doc.hex(), item.hex(), device.hex(),
                              str(version), str(kind), str(epoch), '' if coverage is None else str(coverage),
                              nonce.hex(), body.hex(), info.hex(), key.hex(), aad.hex(), frame.hex(), envelope.hex()]))
    return '\n'.join(rows) + '\n'


if __name__ == '__main__':
    if sys.argv[1:] not in ([], ['--emit']):
        raise SystemExit('usage: check_v1_vectors.py [--emit]')
    expected = generate()
    if sys.argv[1:] == ['--emit']:
        print(expected, end='')
    else:
        path = Path(__file__).resolve().parents[2] / 'test-vectors' / 'sync-item-v1.csv'
        if path.read_text() != expected:
            raise SystemExit('FAIL: v1 fixtures differ from independent oracle')
        print('PASS: 5 independent complete sync-item v1 vectors')
