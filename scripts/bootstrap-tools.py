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
"""Download pinned Linux x86_64 audit tools into this checkout, never globally."""
import hashlib
import io
import json
from pathlib import Path
import platform
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
assert platform.system() == "Linux" and platform.machine() == "x86_64"
output = ROOT / ".tools/bin"
output.mkdir(parents=True, exist_ok=True)
for tool in json.loads((ROOT / "scripts/tools.json").read_text()):
    data = urllib.request.urlopen(tool["url"], timeout=60).read()
    if hashlib.sha256(data).hexdigest() != tool["sha256"]:
        raise SystemExit("Tool checksum mismatch: " + tool["name"])
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        member = next(m for m in archive.getmembers() if m.isfile() and Path(m.name).name == tool["name"])
        target = output / tool["name"]
        target.write_bytes(archive.extractfile(member).read())
        target.chmod(0o755)
    print("Verified tool:", tool["name"], tool["version"])
