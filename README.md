# privatale-cli

Public shared Rust core and Linux CLI for Privatale. The goal is to make the
cryptography, synchronization, conflict resolution and file policies auditable
and reusable by web, Android, iOS and future desktop clients.

**Current status: synthetic cryptography prototype, not a production journal.**
The command currently supports only `--version` and `padme-length`. There is no
persistent journal, login, sync transport, CRDT, key agent or file mirror yet.
The other clients are intended to consume this core; this import does not claim
that they are already integrated. Public source is not a security certification.

## Build and verify

Linux x86_64 is the tested host. Install the pinned Rust toolchain from
`rust-toolchain.toml` with `rustup toolchain install 1.99.1 --profile minimal
--component rustfmt,clippy --target wasm32-unknown-unknown` (on one line).
Use Node 25.2.1 and Python 3.13.7. Independent oracles require Python
`cryptography==43.0.0`, system libsodium and libargon2. Tests load these shared
libraries through ctypes; no production code links against the Python oracles.
See [verification](docs/security/verification.md) for the environment and limits.

```sh
cargo fetch --locked
bash scripts/check-p1.sh
node scripts/check-browser.mjs
```

The first command restores the locked dependency cache. The checks then run
without Cargo network access. The browser runner uses an installed `google-chrome`
(or `CHROME_BIN`), a fresh temporary profile, loopback fixtures and the normal
browser sandbox; it shuts down only its own processes. It has a five-minute
limit. Debug Argon2 tests are intentionally expensive and retain the 64 MiB
parameters. Node/WASM passing does not substitute for a real browser run.

```sh
python3 scripts/bootstrap-tools.py
python3 scripts/check-public-source.py
python3 scripts/check-secrets.py tree
python3 scripts/check-secrets.py history
.tools/bin/cargo-audit audit
.tools/bin/cargo-deny check
```

Audit tools are checksum-pinned and installed only under ignored `.tools/` on
Linux x86_64. Advisory checks require a current online database and fail closed;
there is no vulnerability suppression list. Pre-commit users can run
`pre-commit install` after bootstrapping the tools. CI repeats the checks.

## Layout and design

- `crates/privatale-core`: shared byte profiles, unit/integration tests and
  temporary WASM test bridges; `crates/privatale-cli`: the current command.
- `test-vectors`: immutable synthetic/official vectors shared across runtimes.
- `tests/web` and `tests/oracles`: browser/Node checks and independent encoders.
- [Architecture and adapter boundaries](docs/architecture/boundaries.md).
- [Prototype API and limitations](docs/architecture/prototype.md).
- [Version 1 byte profiles](docs/protocol/crypto-v1.md) and
  [future sync contract boundary](docs/protocol/sync-boundary.md).
- [Security policy](SECURITY.md), [contributing](CONTRIBUTING.md),
  [third-party notices](THIRD_PARTY_NOTICES.md).

Configuration examples are documentation only: the current command does not
load config. Future local settings belong outside the checkout, with secrets
in OS secret storage. No live credentials or personal journals belong in tests.

## License

Copyright (C) 2026 NC Software Engineering

This project is licensed under the **GNU Affero General Public License v3.0 only** (AGPL-3.0-only). See [LICENSE](LICENSE) for the full text, also available at <https://www.gnu.org/licenses/agpl-3.0.html>.

Every source file starts with this header:

```
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
```
