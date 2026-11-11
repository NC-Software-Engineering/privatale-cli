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
from pathlib import Path
import tempfile,subprocess,shutil,json,secrets,string
root=Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='privatale-hook-test-') as tmp:
 d=Path(tmp);(d/'scripts').mkdir();(d/'test-vectors').mkdir();(d/'.tools/bin').mkdir(parents=True)
 for name in ['scripts/check-secrets.py','.gitleaks.toml','.gitignore','test-vectors/hpke-rfc9180.json','.tools/bin/gitleaks']:shutil.copy2(root/name,d/name)
 def cmd(*args):return subprocess.run(args,cwd=d,capture_output=True,text=True)
 assert cmd('git','init','-q').returncode==0
 cmd('git','config','user.name','Synthetic Test');cmd('git','config','user.email','test@example.invalid')
 checks=[]
 def scan(mode,expected,label):
  r=cmd('python3','scripts/check-secrets.py',mode);assert r.returncode==expected,(label,r.stdout,r.stderr);checks.append({'check':label,'exit':r.returncode})
 scan('tree',0,'known-public-vector-accepted')
 cmd('git','add','scripts/check-secrets.py','.gitleaks.toml','.gitignore','test-vectors/hpke-rfc9180.json')
 scan('staged',0,'staged-known-vector-accepted')
 token='ghp_'+''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(36))
 (d/'canary.txt').write_text('github_token = "'+token+'"\n');cmd('git','add','canary.txt')
 (d/'canary.txt').write_text('safe unstaged replacement\n')
 scan('staged',1,'secret-in-index-not-hidden-by-unstaged-edit')
 assert cmd('git','-c','commit.gpgsign=false','commit','-qm','Synthetic scanner regression').returncode==0
 cmd('git','add','canary.txt');assert cmd('git','-c','commit.gpgsign=false','commit','-qm','Remove synthetic token').returncode==0
 scan('history',1,'deleted-historical-secret-detected')
 scan('tree',0,'clean-current-tree')
 (d/'test-vectors/hpke-rfc9180.json').write_text((d/'test-vectors/hpke-rfc9180.json').read_text()+'\n')
 scan('tree',1,'changed-vector-not-allowlisted')
 print(json.dumps(checks))
