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
// Само browser P1 прототип. Използван от временния WASM bridge; няма key storage.
// Host Web Crypto е доверена граница; не доказваме качеството на неговия RNG.
export function generateNonce() {
  const nonce = new Uint8Array(24);
  try {
    if (globalThis.isSecureContext !== true) throw new Error('Insecure context');
    const crypto = globalThis.crypto;
    if (!crypto || typeof crypto.getRandomValues !== 'function') {
      throw new Error('Web Crypto unavailable');
    }
    // Извикване като method запазва native receiver-а.
    if (crypto.getRandomValues(nonce) !== nonce) throw new Error('Invalid Web Crypto result');
    return nonce;
  } catch {
    // Не връщаме частично попълнени данни и не пробваме друг източник.
    nonce.fill(0);
    throw new Error('EntropyUnavailable');
  }
}
