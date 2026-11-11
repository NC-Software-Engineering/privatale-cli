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
"""Independent PTE0 fixture oracle: Python serialization + system libsodium.
Synthetic data only. Default checks frozen CSV; --emit prints candidate CSV, never
updates it. No Rust imports, generated binaries, network or third-party Python deps.
"""
import ctypes as c
import ctypes.util
import pathlib
import sys


def generate():
    path = ctypes.util.find_library("sodium")
    if path is None:
        raise RuntimeError("libsodium is required for independent verification")
    lib = c.CDLL(path)
    lib.sodium_init.restype = c.c_int
    lib.sodium_init.argtypes = []
    if lib.sodium_init() < 0:
        raise RuntimeError("sodium_init failed")
    lib.sodium_version_string.restype = c.c_char_p
    lib.sodium_version_string.argtypes = []
    print("oracle: libsodium " + lib.sodium_version_string().decode(), file=sys.stderr)
    encrypt = lib.crypto_aead_xchacha20poly1305_ietf_encrypt
    encrypt.restype = c.c_int
    encrypt.argtypes = [c.c_void_p, c.POINTER(c.c_ulonglong), c.c_char_p,
                       c.c_ulonglong, c.c_char_p, c.c_ulonglong,
                       c.c_void_p, c.c_char_p, c.c_char_p]
    rows = ["key,nonce,owner,doc,item,key_version,payload,aad,frame,envelope"]
    # Literal independently calculated Padme sizes: 12+0 -> 256; 12+245 -> 272.
    for number, (payload, frame_size) in enumerate([(b"", 256), (bytes(range(245)), 272)]):
        key = bytes(range(32))
        nonce = bytes(range(24)) if number == 0 else bytes(range(24, 48))
        owner = b"golden\x00owner"
        doc = bytes(range(16))
        item = bytes(range(16, 32))
        version = 0x01020304
        aad = (b"privatale-prototype/PTE0\0" + len(owner).to_bytes(4, "little")
               + owner + doc + item + version.to_bytes(4, "little") + bytes(4))
        raw = b"PTP0" + len(payload).to_bytes(8, "little") + payload
        frame = raw + bytes(frame_size - len(raw))
        output = c.create_string_buffer(len(frame) + 16)
        output_length = c.c_ulonglong()
        result = encrypt(output, c.byref(output_length), frame, len(frame), aad,
                         len(aad), None, nonce, key)
        if result != 0 or output_length.value != len(frame) + 16:
            raise RuntimeError("libsodium encryption failed")
        envelope = b"PTE0" + nonce + output.raw
        rows.append(",".join([key.hex(), nonce.hex(), owner.hex(), doc.hex(), item.hex(),
                              str(version), payload.hex(), aad.hex(), frame.hex(), envelope.hex()]))
    return "\n".join(rows) + "\n"


if __name__ == "__main__":
    if sys.argv[1:] not in ([], ["--emit"]):
        raise SystemExit("usage: check_pte0_vectors.py [--emit]")
    expected = generate()
    if sys.argv[1:] == ["--emit"]:
        print(expected, end="")
    else:
        saved = pathlib.Path(__file__).resolve().parents[2] / "test-vectors" / "pte0.csv"
        if saved.read_text() != expected:
            raise SystemExit("FAIL: frozen PTE0 fixtures differ from libsodium oracle")
        print("PASS: 2 complete PTE0 golden vectors independently verified")
