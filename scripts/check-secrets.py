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
"""Fail closed; print only rule, file and line, never matched values or raw logs."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MODE = sys.argv[1] if len(sys.argv) == 2 else ""
if MODE not in {"staged", "tree", "history"}:
    raise SystemExit("usage: check-secrets.py staged|tree|history")
TOOL = ROOT / ".tools/bin/gitleaks"
VECTOR = "test-vectors/hpke-rfc9180.json"
VECTOR_HASH = "d6ba16f2ced6962546579402c9e230e56d1ee498e31ec813518e1972e4b1ca74"

def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, stderr=subprocess.DEVNULL)

def known_vector(finding):
    if finding["RuleID"] != "generic-api-key" or finding["File"] != VECTOR:
        return False
    try:
        if MODE == "history":
            commit = finding.get("Commit", "")
            if not re.fullmatch(r"[a-f0-9]{40,64}", commit):
                return False
            data = git("show", f"{commit}:{VECTOR}")
        elif MODE == "staged":
            data = git("show", ":" + VECTOR)
        else:
            data = (ROOT / VECTOR).read_bytes()
        return hashlib.sha256(data).hexdigest() == VECTOR_HASH and finding["StartLine"] in {14, 15, 16, 17, 19}
    except (OSError, subprocess.CalledProcessError):
        return False

with tempfile.TemporaryDirectory(prefix="privatale-scan-") as temporary:
    temp = Path(temporary)
    report = temp / "report.json"
    if MODE == "history":
        command = ["git", "--log-opts=--all --full-history", str(ROOT)]
    else:
        snapshot = temp / "tree"
        snapshot.mkdir()
        if MODE == "staged":
            paths = git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z").split(b"\0")
        else:
            paths = git("ls-files", "--cached", "--others", "--exclude-standard", "-z").split(b"\0")
        for raw in sorted(set(paths)):
            if not raw:
                continue
            name = raw.decode("utf-8")
            rel = Path(name)
            if rel.is_absolute() or ".." in rel.parts or ".git" in rel.parts:
                raise SystemExit("Unsafe export path")
            original = ROOT / rel
            if original.is_symlink():
                raise SystemExit("Symlink refused in public source")
            if MODE == "staged":
                if git("ls-files", "--stage", "--", name).startswith(b"120000 "):
                    raise SystemExit("Staged symlink refused")
                data = git("show", ":" + name)
            else:
                if not original.exists():
                    continue
                data = original.read_bytes()
            target = snapshot / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        command = ["dir", str(snapshot)]
    result = subprocess.run([
        str(TOOL), *command, "--config", str(ROOT / ".gitleaks.toml"),
        "--ignore-gitleaks-allow", "--gitleaks-ignore-path", str(temp / "no-ignore-file"),
        "--redact=100", "--no-banner", "--report-format=json", "--report-path", str(report),
    ], cwd=ROOT, capture_output=True)
    if result.returncode not in {0, 1} or not report.exists():
        raise SystemExit("FAIL: Gitleaks execution; raw diagnostics withheld")
    findings = json.loads(report.read_text())
    unexpected = []
    for finding in findings:
        # Directory mode may return an absolute source path; normalize for review.
        if MODE != "history":
            path = Path(finding["File"])
            if path.is_absolute():
                finding["File"] = str(path.relative_to(snapshot))
        if not known_vector(finding):
            unexpected.append(finding)
    for finding in unexpected:
        print(json.dumps({key: finding[key] for key in ("RuleID", "File", "StartLine")}))
    print(json.dumps({"mode": MODE, "unexpected": len(unexpected), "verified_public_vector": len(findings) - len(unexpected)}))
    raise SystemExit(1 if unexpected else 0)
