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
"""Check publishable paths, full source headers, public fixtures and local links."""
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
header = (ROOT / "scripts/license-header.txt").read_text()
files = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT).split(b"\0")
failures = []
for raw in sorted(set(files)):
    if not raw:
        continue
    rel = Path(raw.decode())
    path = ROOT / rel
    if not path.exists():
        continue
    if path.is_symlink() or any(p in {".ai", ".pi", "ptapi", "ptapp", "ptweb", "target", "node_modules", "__pycache__"} for p in rel.parts):
        failures.append((str(rel), "forbidden-path")); continue
    data = path.read_text()
    source = path.suffix in {".rs", ".mjs", ".js", ".py", ".sh", ".html"}
    if source:
        prefix = header
        if path.suffix in {".py", ".sh"}:
            prefix = "\n".join("#" + line[2:] for line in header.splitlines()) + "\n"
        elif path.suffix == ".html":
            prefix = "<!--\n" + "\n".join(line[3:] if line.startswith("// ") else "" for line in header.splitlines()) + "\n-->\n"
        content = data.split("\n", 1)[1] if data.startswith("#!") else data
        if not content.startswith(prefix):
            failures.append((str(rel), "license-header"))
    for category, pattern in {
        "private-workstation-path": r"/(?:home|Users)/[A-Za-z][A-Za-z0-9_.-]+",
        "operational-endpoint": r"https?://[a-z0-9.-]+\.(?:azurewebsites\.net|mongo\.cosmos\.azure\.com|blob\.core\.windows\.net|internal)\b",
        "private-plan-reference": r"\b(?:PLAN[1-5]|PRD[1-5])\b",
    }.items():
        if re.search(pattern, data, re.I):
            failures.append((str(rel), category))
    if path.suffix == ".md":
        for link in re.findall(r"\]\(([^)]+)\)", data):
            if not re.match(r"[a-z]+:|#", link) and not (path.parent / link.split("#")[0]).exists():
                failures.append((str(rel), "broken-local-link"))
for name, digest in json.loads((ROOT / "test-vectors/sha256.json").read_text()).items():
    if hashlib.sha256((ROOT / "test-vectors" / name).read_bytes()).hexdigest() != digest:
        failures.append((name, "fixture-integrity"))
for item in failures:
    print(json.dumps({"file": item[0], "rule": item[1]}))
if failures:
    raise SystemExit(1)
print("PASS: public paths, source headers, fixture integrity and local links")
