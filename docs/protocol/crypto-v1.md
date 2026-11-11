# Synthetic crypto byte profiles

This document describes the current source and immutable vectors. It is not a
production protocol acceptance, enrollment implementation or independent audit.
Native Rust, WASM/Node, real-browser and Python oracle checks cover the same
bytes. Deterministic fixture APIs are not normal randomness-generating wrappers.

## Conventions and padding

`||` means concatenation; integer suffixes `LE32`/`LE64` specify unsigned little
endian encoding. UUIDs are exactly 16 raw network-order bytes, not a host Guid
memory representation. Domain strings below end with a single zero byte (`\0`).
Keys are 32 bytes. XChaCha20-Poly1305 uses a 24-byte nonce and 16-byte tag.
Every normal encryption obtains fresh OS/Web Crypto randomness; entropy errors
fail closed. Random nonces have negligible, not zero, collision probability.

Padmé first clamps input to at least 256 bytes. For length L, let
E = floor(log2(L)), S = floor(log2(E)) + 1, then round L upward to a multiple of
2^(E-S). Overflow is refused. Padding is zero bytes and decoding checks that it
is canonical. AEAD authentication precedes plaintext-frame validation.

## Inline sync items

Source: [sync_item_v1.rs](../../crates/privatale-core/src/sync_item_v1.rs).
Kinds: change=1, snapshot=2, epoch=3, purge=4, embedding=5. Key version must be
positive. Only snapshot carries `covers_up_to_seq`; its value is at most signed
64-bit maximum. Epoch is u64. Invalid context is rejected before encryption.

- Document key: HKDF-SHA256 with IKM=AMK, no supplied salt, 32-byte output;
  info=`privatale/document-key/hkdf-sha256/v1\0 || docId || keyVersion:LE32`.
- Plaintext: `PTP1 || bodyLength:LE64 || body || zero padding`, padded as a whole.
- Envelope: `PTI1 || nonce24 || ciphertext || tag16`.
- AAD, in order:
  `privatale/sync-item/aad/v1\0 || ownerId || docId || itemId || keyVersion:LE32 ||
  formatVersion(1):LE32 || kind:u8 || epoch:LE64 || deviceId || coversPresent:u8 ||
  coversValueOrZero:LE64 || PTI1 || nonce24`.
- Total size is `Padme(12+bodyLength)+44`, at most 1,048,576 bytes. Largest body
  accepted is 1,032,180 bytes. Larger content needs a separately specified blob
  transport, not a relaxed inline limit.

Open rejects an invalid size/header/context, failed tag, noncanonical frame or
padding. `seal_with_nonce` is explicitly deterministic; normal Linux `seal`
obtains its nonce with `getrandom`. Browser code supplies checked Web Crypto
bytes through the temporary ABI.

Server-assigned sequence/received time and blob location are not included in
this AAD. Authenticated device/coverage fields do not prove a particular device's
identity against another holder of the same AMK, correct ordering, or truthful
snapshot coverage. Replay, epoch, coverage semantics and blob ownership require
additional checks in the future sync implementation before history is discarded.

## AMK wrappers

Source: [amk_v1.rs](../../crates/privatale-core/src/amk_v1.rs).
Context C=`ownerId || envelopeId || amkVersion:LE32 || formatVersion:LE32`.
AMK version is positive, format version is 1. A new random envelope UUID is a
caller obligation. Plaintext is exactly 256 bytes: `PTA1 || AMK32 || zeros220`.
Wrappers do not implement enrollment, key storage, sender trust or rotation.

| Wrapper | Header and key | Associated data |
| --- | --- | --- |
| Device | `PTK1 || encapsulatedKey32`; RFC9180 Base HPKE X25519/HKDF-SHA256/ChaCha20Poly1305, info=`privatale/amk/device/hpke/v1\0 || C || deviceId || recipientPublicKey32` | `privatale/amk/device/aad/v1\0 || C || deviceId || recipientPublicKey32 || header` |
| Recovery | `PTR1 || nonce24`; HKDF-SHA256(IKM=random recovery secret32, no supplied salt, info=`privatale/amk/recovery/key/v1\0 || C`) | `privatale/amk/recovery/aad/v1\0 || C || header` |
| Password | `PTW1 || salt16 || mKiB:LE32 || t:LE32 || p:LE32 || nonce24`; Argon2id v19 followed by HKDF-SHA256(no supplied salt, info=`privatale/amk/password/key/v1\0 || C`) | `privatale/amk/password/aad/v1\0 || C || header` |

Encrypted plaintext/tag follow the header. Total lengths are exactly 308, 300
and 328 bytes respectively. Recovery/password use XChaCha20-Poly1305; HPKE uses
its standard ChaCha20Poly1305 AEAD (not a home-grown HPKE construction).

Password input is 1–1024 bytes of valid UTF-8, without normalization. Allowed
Argon2id tuples are only `(65536 KiB,3,1)` and `(65536 KiB,4,1)`, 32-byte output;
t3 is default, t4 is an explicit upgrade. Other tuples are rejected before KDF
allocation. The caller-owned 64 MiB arena and intermediate output are wiped.
Rewrapping returns a new envelope; it performs no server replacement and changes
no recovery/device envelope. Base HPKE does **not** authenticate the sender.

## Streaming blobs

Source: [blob_v1.rs](../../crates/privatale-core/src/blob_v1.rs).
Class 1 is media, class 2 is a sync blob. Context bytes:

- Media: `ownerId || docId || blobId || formatVersion(1):LE32`.
- Sync: the inline AAD context fields from ownerId through coversValueOrZero
  (without the domain, PTI1 or nonce), followed by blobId.

Header H=`PTB1 || class:u8 || randomStreamId32 || paddedLength:LE64` (45 bytes).
Stream key is HKDF-SHA256(IKM=caller base key32, salt=streamId32,
info=`privatale/blob/key/v1\0 || class:u8 || contextBytes`), 32-byte output.
Media callers must supply an independently random file key; sync callers supply
the appropriate document key. The primitive accepts a base key and cannot prove
that the caller selected or stored it correctly.

Plaintext is `PTM1` (media) or `PTP1` (sync), followed by bodyLength:LE64,
body and canonical zero padding. Padmé applies once to the entire plaintext.
The result is split into at most 65,536-byte plaintext records. Each wire record
is `freshNonce24 || ciphertext || tag16`. Record AAD is
`privatale/blob/chunk/aad/v1\0 || contextBytes || H || index:LE64 || final:u8 ||
recordPlaintextLength:LE32`. Index starts at zero; final is 1 only on the last
record. The encoder may require a final padding-only record with zero body input.

Maximum body is 5,000,000,000 bytes; maximum padded length P is 5,033,164,800.
For N=ceil(P/65536), total wire size is `45+P+40*N`, at most 5,036,236,845.
Size checks do not allocate a file-sized buffer. The reader accepts exactly one
record per call. Any error, early/duplicate finish or extra record poisons that
instance irreversibly. Returned prefixes are authenticated but cannot be
retracted. **A successful `finish` is mandatory before committing the file.**

## Errors, memory and older experiments

Shared errors are `InvalidContext`, `TooLarge`, `InvalidEnvelope`,
`Authentication`, `InvalidFrame` and `EntropyUnavailable`. JS maps failures to
bounded errors and clears WASM input/output; it cannot guarantee wiping every
GC/caller/library copy. The temporary pointer-free browser ABI exposes no raw
memory addresses and allows one active streaming handle per adapter. It is not
a stable application ABI.

Earlier PTP0/PTE0 framing, AAD and HKDF experiments are retained in separate
`framing`, `envelope`, `keys` and `linux_crypto` modules and their tests. They
must never be auto-detected as fallback inputs to v1. Source and independent
vectors document those experiments; they are not an alternative product format.
The migration changes crate/fixture paths and licensing, not these bytes.
