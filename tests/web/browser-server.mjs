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
// Local synthetic harness only: exact allowlist, loopback, no directory listing.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
const root = new URL('../../', import.meta.url);
const routes = new Map([
  ['/', ['tests/web/index.html', 'text/html; charset=utf-8']],
  ['/check.mjs', ['tests/web/check.mjs', 'text/javascript; charset=utf-8']],
  ['/nonce.mjs', ['tests/web/nonce.mjs', 'text/javascript; charset=utf-8']],
  ['/crypto-v1.mjs', ['tests/web/crypto-v1.mjs', 'text/javascript; charset=utf-8']],
  ['/check-v1.mjs', ['tests/web/check-v1.mjs', 'text/javascript; charset=utf-8']],
  ['/bridge-v1.wasm', ['target/wasm32-unknown-unknown/debug/examples/browser_v1.wasm', 'application/wasm']],
  ['/crypto.mjs', ['tests/web/crypto.mjs', 'text/javascript; charset=utf-8']],
  ['/bridge.wasm', ['target/wasm32-unknown-unknown/debug/examples/browser_bridge.wasm', 'application/wasm']],
  ['/core.wasm', ['target/wasm32-unknown-unknown/debug/privatale_core.wasm', 'application/wasm']],
  ['/vectors.wasm', ['target/wasm32-unknown-unknown/debug/examples/framing_vectors.wasm', 'application/wasm']],
  ['/padme.csv', ['test-vectors/padme.csv', 'text/plain; charset=utf-8']],
]);
const server = createServer(async (request, response) => {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'");
  const route = routes.get(request.url);
  if (request.method !== 'GET' || !route) {
    response.writeHead(404).end('Not found');
    return;
  }
  try {
    const contents = await readFile(new URL(route[0], root));
    response.writeHead(200, { 'Content-Type': route[1] }).end(contents);
  } catch {
    response.writeHead(500).end('Build the WASM targets first.');
  }
});
server.listen(0, '127.0.0.1', () => {
  console.log(`Browser harness: http://127.0.0.1:${server.address().port}/`);
});
// Bounded lifetime if the operator forgets to stop the local process.
setTimeout(() => server.close(), 15 * 60 * 1000).unref();
