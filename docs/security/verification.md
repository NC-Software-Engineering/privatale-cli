# Verification and reproducibility

The initial workspace preserves the existing cryptographic behavior while
splitting library and command. The command remains `privatale-prototype`.
All eight CSV/JSON vector files retain their original bytes. All 42 external
Cargo.lock package records remain unchanged. Workspace package records and
imports/fixture paths are the intentional structural changes.

Local reference environment: Linux x86_64, Rust/Cargo 1.99.1, Node 25.2.1,
Python 3.13.7, cryptography 43.0.0, libsodium 1.0.18 (distribution package
1.0.18-1ubuntu0.25.10.1), libargon2 package 0~20190702+dfsg-4build1.
Chromium version is recorded by the browser runner. The lockfile fixes Rust
dependencies; CI pins the Ubuntu 24.04 amd64 oracle packages to libsodium23
1.0.18-1ubuntu0.24.04.1 and libargon2-1 0~20190702+dfsg-4build1, and prints their
installed versions. A missing package version fails instead of silently
substituting another one. GitHub's Ubuntu runner and browser receive updates,
so byte-for-byte identical binaries across
all future runner images are not promised. The shared byte vectors must still
match exactly. Runtime changes require observing the full suite again.

`scripts/check-p1.sh` covers 39 native assertions/tests, 12 JS adapter tests,
24 shared Padmé vectors, native/Node WASM cases, independent Python oracles,
formatting/clippy and Argon2 measurements. `scripts/check-browser.mjs` executes
the actual synthetic page with a fresh Chrome profile and verifies the completed
result, including AMK/blob, Web Crypto entropy failures and t3/t4 Argon2 tuples.
Build success or Node WASM results alone are not browser acceptance.

Public-source and secret checks operate on publishable paths. The pre-commit
scanner reads exact staged bytes (not unstaged replacements); the CI scans the
tree and full public history. Only five generic-api-key detections in the exact
known official HPKE JSON vector may be classified as public test material,
after a SHA-256 check. No blanket test-directory allowlist or baseline is used.
Raw matches and scan diagnostics are withheld; reports show rule/path/line only.
URL/path checks supplement secret detection, but do not prove absence of all
personal data or undisclosed secrets.

Audit/deny tools are pinned in `scripts/tools.json`. Advisory results require
successful database refresh and are separate from crypto test evidence. A green
test suite never overrides an advisory failure. CI does not publish packages,
deploy a service, receive production secrets or upload raw evidence. Required
checks, branch rules and private vulnerability reporting are repository-admin
settings to verify before the first approved code push.

The local preparation and its private source mapping are reviewed before
publication. Hosted CI results can only be observed after an approved push;
local success is not a claim that hosted jobs have already run.

Observed locally on 2026-11-11: the pre-split and migrated full suites both
passed (39 native, 12 JS plus shared WASM/oracle checks); real Chrome
157.0.8103.50 completed the migrated page with all expected counters. RustSec
audit and cargo-deny passed after database refresh. Six isolated scanner cases
covered official-vector acceptance, staged-byte inspection, historical deleted
credentials and rejection of a modified vector. These observations use only
synthetic data and do not establish production readiness or hosted CI success.
