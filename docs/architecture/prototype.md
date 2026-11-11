# Isolated synthetic P1 prototype

Implements the documented synthetic v1 byte profiles, not a production client or
security audit. No real data, persistence, enrollment, sync apply/commit,
network/storage services, deployment, or persistent-client implementation. Existing v0
fixtures and browser bridge stay separate and unchanged.

## Run

From the repository root, with the pinned toolchain/target available:

```sh
export PATH="$HOME/.cargo/bin:$PATH"
bash scripts/check-p1.sh
```

All checks fail on assertions/nonzero commands. The script includes the previous
regression command, new native and actual WASM shared tests, JS adapter tests,
independent Python oracles and native/WASM Argon2 measurements. Python requires
`cryptography`, system `libsodium` and `libargon2`; no package installation is
performed by the checks. Assertions must be enabled. `--emit` on an oracle only
prints candidate fixture bytes; default operation never rewrites fixtures.

For **parent-observed actual Chromium**, after the builds:

```sh
node tests/web/browser-server.mjs
```

Open the printed `http://127.0.0.1:<port>/` in Chromium. Keep the page open until
its JSON result appears (debug Argon2 tests take time). Inspect
`globalThis.prototypeResult` in DevTools: overall `status` must be `PASS`, with
`amkSharedTests=4`, `blobSharedTests=4`, `p1.status=PASS`, `p1.deviceChecks=2`,
`p1.entropyFailures=15`, and both Argon2 t3/t4 timing entries. Every Rust test
export must actually finish without a WASM trap; status is only set after all
checks. Preserve browser/version and the result as synthetic evidence. The
loopback exact-allowlist server expires after 15 minutes; Ctrl-C stops it sooner.
Node/WASM results do **not** establish actual Chromium observation. Browser results are synthetic prototype evidence, not production acceptance.

## API and resource boundaries

- `sync_item_v1` is unchanged and inline-only, C <= 1,048,576 bytes.
- `amk_v1`: standard RFC9180 Base X25519/HKDF-SHA256/ChaCha20Poly1305 from pinned
  `hpke=0.15.1`; Base **does not authenticate sender identity**. Recipient trust,
  enrollment and rotation authorization are outside this API. Context IDs are
  caller-supplied raw network-order bytes; caller must create a new random UUID
  envelopeId for every wrap. Fixtures intentionally use fixed synthetic IDs.
- Linux `device_seal`, `recovery_seal`, `password_seal` obtain fallible OS entropy.
  Functions prefixed `fixture_` are explicit deterministic test/browser-entropy
  boundaries, not safe normal application wrappers. Browser callers use only
  `tests/web/crypto-v1.mjs`, which obtains fresh Web Crypto bytes without fallback.
  Recovery/file keys must be independently random 32-byte secrets supplied by
  the caller; password bytes are UTF-8, without normalization.
- Password allowlist revision 1 is exactly (65536 KiB,3,1) and (65536 KiB,4,1).
  `upgrade=false` selects t3; explicit `true` selects t4. Unknown tuples are
  refused before KDF/arena allocation. Rewrapping only creates a new password
  envelope; no API mutates recovery/device envelopes or performs server replace.
  The 64 MiB arena and raw/derived KDF output are explicitly zeroized. Library,
  JS/GC and caller copies cannot all be guaranteed erased.
- `blob_v1::Encoder`/`Reader` retain only bounded record buffers. `sizes` checks
  5,000,000,000 original bytes, P <= 5,033,164,800 and C <= 5,036,236,845 without
  allocating the file. Padme applies once, not per chunk. Call `next_body_len`
  for each encoder input; padding-only final records can require zero body bytes.
  Reader accepts exactly one record per call and releases only authenticated
  body prefixes. **Prefixes are not full-file completion**. Mandatory successful
  `finish` is required; any error, early finish, extra record or repeat finish
  irreversibly poisons that instance. Sync callers must not apply before finish.
- The separate `browser-v1` pointer-free ABI never exports addresses. JS checks
  owned byte views (rejects shared buffers), integer versions and BigInt/u64
  values, clears WASM input/output after every call, invalidates active stream
  handles on failure, and transfers <=65,576 bytes per streaming record. One
  active stream per adapter. Returned plaintext belongs to the caller; a later
  failure cannot retract an already consumed prefix. There are no storage APIs.

## Vectors, dependencies and gaps

`test-vectors/amk-v1.csv` freezes all wrapper intermediates/full envelopes, including
t3/t4; `test-vectors/blob-v1.csv` freezes full body, key, header, per-record AAD and
records for both classes at 0/244/245/65523/65524/65525/131061 bytes. The same
Rust test source and `include_str!` vectors execute natively and in WASM.
Independent encoders use Python HKDF, OpenSSL X25519/ChaCha, libsodium XChaCha and
libargon2. The HPKE Python encoder is fixture-only, never production crypto.

`hpke-rfc9180.json` is the official mode0/kem32/kdf1/aead3 vector from
https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/master/test-vectors.json;
`hpke-official.csv` freezes its first seal operation for shared Rust/WASM tests.
RFC9106 §5.3 Argon2id KAT is tested in Rust/WASM and independent libargon2;
its small-memory/secret/AD settings are never accepted by the AMK wrapper.

Direct crypto dependencies are exact-pinned and transitive versions/checksums
are frozen in Cargo.lock; offline builds verify availability and WASM parity.
Dependency manifests/source/feature graph were inspected, including all-zero DH
rejection and Argon2 arena cleanup. `cargo-audit` was unavailable during the original prototype checks:
**those original checks did not establish a current advisory database audit**.
This checkout adds a separate advisory check; see the migration verification record.
No independent dependency security audit is claimed. No global installer, publish or deployment was used. Timing
measurements are debug-build local observations, not latency guarantees or an
excuse to lower approved parameters.
