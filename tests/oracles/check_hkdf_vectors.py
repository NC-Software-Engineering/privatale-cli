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
"""Independent prototype HKDF fixtures: Python stdlib HMAC/SHA256, no Rust.
Default is read-only comparison; --emit prints candidates for explicit review.
All AMKs here are public synthetic fixtures, never real keys.
"""
import hashlib
import hmac
from pathlib import Path
import sys


def hkdf(ikm, salt, info, size):
    prk = hmac.digest(salt, ikm, hashlib.sha256)
    output = b""
    block = b""
    for counter in range(1, (size + 31) // 32 + 1):
        block = hmac.digest(prk, block + info + bytes([counter]), hashlib.sha256)
        output += block
    return output[:size]


def candidates():
    # RFC 5869 Appendix A.3: SHA256, no salt/info, multi-block output.
    expected = bytes.fromhex(
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8")
    if hkdf(bytes([11]) * 22, b"", b"", 42) != expected:
        raise RuntimeError("RFC 5869 case 3 oracle self-check failed")
    base = bytes(range(32))
    doc = bytes(range(16))
    cases = [(base, doc, 0), (base, doc, 0x01020304),
             (base, bytes(range(16, 32)), 0), (bytes(reversed(base)), doc, 0),
             (base, doc, 0xFFFFFFFF)]
    rows = ["amk,doc,key_version,info,key"]
    for amk, document, version in cases:
        info = (b"privatale-prototype/document-key/HKDF-SHA256/v0\0"
                + document + version.to_bytes(4, "little"))
        key = hkdf(amk, b"", info, 32)
        rows.append(",".join([amk.hex(), document.hex(), str(version), info.hex(), key.hex()]))
    return "\n".join(rows) + "\n"


if __name__ == "__main__":
    if sys.argv[1:] not in ([], ["--emit"]):
        raise SystemExit("usage: check_hkdf_vectors.py [--emit]")
    expected = candidates()
    if sys.argv[1:] == ["--emit"]:
        print(expected, end="")
    else:
        fixture = Path(__file__).resolve().parents[2] / "test-vectors" / "hkdf.csv"
        if fixture.read_text() != expected:
            raise SystemExit("FAIL: frozen HKDF vectors differ from independent oracle")
        print("PASS: RFC 5869 + 5 independent prototype document-key vectors")
