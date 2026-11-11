// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 NC Software Engineering
//
// This file is part of privatale-cli.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
// Runs the existing synthetic page in a disposable real Chrome profile.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { EventEmitter, once } from 'node:events';

const root = fileURLToPath(new URL('../', import.meta.url));
const profile = await mkdtemp(join(tmpdir(), 'privatale-browser-'));
let browser;
const server = spawn(process.execPath, ['tests/web/browser-server.mjs'], { cwd: root, stdio: ['ignore', 'pipe', 'pipe'] });
const pending = new Map();
const events = new EventEmitter();
let nextId = 0;
let buffer = '';
const timer = setTimeout(() => { console.error('FAIL: browser timeout'); process.exitCode = 1; browser?.kill(); server.kill(); }, 300_000);
async function stop(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const done = new Promise(resolve => child.once('exit', resolve));
  child.kill();
  const force = setTimeout(() => child.kill('SIGKILL'), 3000);
  await done;
  clearTimeout(force);
}
function call(method, params = {}, sessionId) {
  const id = ++nextId;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    browser.stdio[3].write(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }) + '\0');
  });
}
try {
  const url = await new Promise((resolve, reject) => {
    let output = '';
    server.once('error', reject);
    server.once('exit', () => reject(new Error('Harness exited')));
    server.stdout.on('data', chunk => {
      output += chunk;
      const match = output.match(/http:\/\/127\.0\.0\.1:\d+\//);
      if (match) resolve(match[0]);
    });
  });
  browser = spawn(process.env.CHROME_BIN || 'google-chrome', [
    '--headless=new', '--remote-debugging-pipe', `--user-data-dir=${profile}`,
    '--no-first-run', '--no-default-browser-check', '--disable-background-networking',
    '--disable-component-update', '--disable-sync', '--disable-extensions',
    '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1', 'about:blank',
  ], { stdio: ['ignore', 'ignore', 'pipe', 'pipe', 'pipe'] });
  const rejectPending = () => { for (const p of pending.values()) p.reject(new Error('Browser exited')); pending.clear(); events.emit('browser-exit'); };
  browser.once('error', rejectPending);
  browser.once('exit', rejectPending);
  browser.stderr.resume(); // Browser diagnostics are not the test result.
  browser.stdio[4].on('data', chunk => {
    buffer += chunk.toString();
    let index;
    while ((index = buffer.indexOf('\0')) >= 0) {
      const message = JSON.parse(buffer.slice(0, index)); buffer = buffer.slice(index + 1);
      if (message.method) events.emit(message.method, message);
      const p = pending.get(message.id);
      if (p) { pending.delete(message.id); message.error ? p.reject(new Error('CDP command failed')) : p.resolve(message.result); }
    }
  });
  const version = await call('Browser.getVersion');
  const { targetId } = await call('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await call('Target.attachToTarget', { targetId, flatten: true });
  await call('Page.enable', {}, sessionId);
  const loaded = once(events, 'Page.loadEventFired');
  await call('Page.navigate', { url }, sessionId);
  await Promise.race([loaded, once(events, 'browser-exit').then(() => { throw new Error('Browser exited before load'); })]);
  // Wait for the page's completed assertions, not a DOM snapshot or a build.
  const evaluated = await call('Runtime.evaluate', {
    expression: `new Promise((resolve, reject) => {
      const end = Date.now() + 270000;
      const poll = () => {
        if (globalThis.prototypeResult) return resolve(globalThis.prototypeResult);
        if (Date.now() > end) return reject(new Error('Harness timeout'));
        setTimeout(poll, 100);
      }; poll();
    })`, awaitPromise: true, returnByValue: true,
  }, sessionId);
  assert.equal(evaluated.exceptionDetails, undefined);
  const result = evaluated.result.value;
  assert.equal(result.status, 'PASS');
  assert.equal(result.secureContext, true);
  for (const [field, count] of Object.entries({ padmeVectors: 24, framingTests: 6, envelopeTests: 5, hkdfTests: 3, syncItemV1Tests: 4, amkSharedTests: 4, blobSharedTests: 4, nonceSamples: 32, entropyFailureCases: 3, bridgeRoundtrips: 3, bridgeRefusals: 3, bridgeEntropyRefusals: 3 })) assert.equal(result[field], count, field);
  assert.equal(result.p1.status, 'PASS');
  assert.equal(result.p1.deviceChecks, 2);
  assert.equal(result.p1.entropyFailures, 15);
  assert.equal(result.p1.streamClasses, 2);
  assert.equal(result.p1.streamSizes, 5);
  assert.deepEqual(result.p1.argon.map(x => [x.mKiB, x.t, x.p]), [[65536, 3, 1], [65536, 4, 1]]);
  console.log(JSON.stringify({ status: 'PASS', browser: version.product, checks: result }));
} catch {
  console.error('FAIL: real browser assertions or browser startup');
  process.exitCode = 1;
} finally {
  clearTimeout(timer);
  await stop(browser);
  await stop(server);
  await rm(profile, { recursive: true, force: true });
}
