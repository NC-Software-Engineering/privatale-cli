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
"""Independent fixture-only encoder: Python RFC9180, OpenSSL X25519/ChaCha,
libargon2 and libsodium. Never imported by the Rust implementation."""
import ctypes as c
import ctypes.util
import hashlib
import hmac
import struct
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def u32(n): return struct.pack('<I', n)
def u64(n): return struct.pack('<Q', n)
def extract(salt, data): return hmac.digest(salt, data, 'sha256')
def expand(prk, info, length=32):
    result = b''; prev = b''
    for i in range(1, (length+31)//32+1):
        prev = hmac.digest(prk, prev+info+bytes([i]), 'sha256'); result += prev
    return result[:length]
def hkdf(ikm, info, salt=b''): return expand(extract(salt, ikm), info)
def padded(n):
    n = max(256,n); e = n.bit_length()-1; s = e.bit_length(); q = 1 << (e-s)
    return ((n+q-1)//q)*q

def xseal(key, nonce, aad, frame):
    lib = c.CDLL(ctypes.util.find_library('sodium'))
    fn = lib.crypto_aead_xchacha20poly1305_ietf_encrypt
    fn.argtypes = [c.c_void_p,c.POINTER(c.c_ulonglong),c.c_char_p,c.c_ulonglong,c.c_char_p,c.c_ulonglong,c.c_void_p,c.c_char_p,c.c_char_p]
    fn.restype = c.c_int
    out = c.create_string_buffer(len(frame)+16); n = c.c_ulonglong()
    if fn(out,c.byref(n),frame,len(frame),aad,len(aad),None,nonce,key) != 0 or n.value != len(frame)+16:
        raise RuntimeError('libsodium failure')
    return out.raw

def argon(password,salt,t,m=65536,p=1,length=32):
    lib = c.CDLL(ctypes.util.find_library('argon2'))
    fn=lib.argon2id_hash_raw
    fn.argtypes=[c.c_uint32,c.c_uint32,c.c_uint32,c.c_char_p,c.c_size_t,c.c_char_p,c.c_size_t,c.c_void_p,c.c_size_t]
    fn.restype=c.c_int
    out=c.create_string_buffer(length)
    if fn(t,m,p,password,len(password),salt,len(salt),out,length)!=0: raise RuntimeError('argon2 failure')
    return out.raw

def hpke(ikm,pk,info,aad,plaintext):
    kem=b'KEM'+bytes.fromhex('0020'); suite=b'HPKE'+bytes.fromhex('002000010003')
    def le(suite,salt,label,ikm): return extract(salt,b'HPKE-v1'+suite+label+ikm)
    def lx(suite,prk,label,info,n): return expand(prk,struct.pack('>H',n)+b'HPKE-v1'+suite+label+info,n)
    sk=lx(kem,le(kem,b'',b'dkp_prk',ikm),b'sk',b'',32)
    priv=X25519PrivateKey.from_private_bytes(sk)
    enc=priv.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    shared=lx(kem,le(kem,b'',b'eae_prk',priv.exchange(X25519PublicKey.from_public_bytes(pk))),b'shared_secret',enc+pk,32)
    ctx=b'\0'+le(suite,b'',b'psk_id_hash',b'')+le(suite,b'',b'info_hash',info)
    secret=le(suite,shared,b'secret',b'')
    key=lx(suite,secret,b'key',ctx,32); nonce=lx(suite,secret,b'base_nonce',ctx,12)
    return enc,key,nonce,ChaCha20Poly1305(key).encrypt(nonce,plaintext,aad)

def public(sk): return X25519PrivateKey.from_private_bytes(sk).public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
def csv(rows): return '\n'.join(','.join(str(v) if isinstance(v,(str,int)) else v.hex() for v in row) for row in rows)+'\n'
