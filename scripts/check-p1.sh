#!/usr/bin/env bash
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
# Complete synthetic P1 local checks; NO browser/production acceptance is inferred.
set -euo pipefail
if (( $# > 1 )) || { (( $# == 1 )) && [[ $1 != . ]]; }; then
  printf '%s\n' 'usage: check-p1.sh [.]' >&2
  exit 2
fi
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
python3 tests/oracles/check_v1_vectors.py
cargo fmt --all --check
cargo test --workspace --locked --offline
cargo clippy --workspace --locked --offline --all-targets -- -D warnings
cargo build -p privatale-core --locked --offline --lib --target wasm32-unknown-unknown
cargo build --locked --offline --example framing-vectors --target wasm32-unknown-unknown
cargo build --locked --offline --example browser-bridge --target wasm32-unknown-unknown
cargo build --locked --offline --example browser-v1 --target wasm32-unknown-unknown
cargo build --locked --offline --bin privatale-prototype
node tests/web/wasm.mjs
node --experimental-vm-modules --test tests/web/browser-nonce.test.mjs tests/web/browser-bridge.test.mjs tests/web/browser-v1.test.mjs
python3 tests/oracles/check_pte0_vectors.py
python3 tests/oracles/check_hkdf_vectors.py
python3 tests/oracles/check_amk_vectors.py
python3 tests/oracles/check_blob_vectors.py
cargo run --locked --offline --example argon-cost
printf '%s\n' 'PASS: synthetic local P1 checks; actual Chromium observation and independent review still REQUIRED.'
