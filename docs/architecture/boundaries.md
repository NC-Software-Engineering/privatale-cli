# Shared core and host boundaries

The public core owns serialization, cryptographic verification and, as those
features are implemented, document/CRDT, synchronization, conflict and file
policies. The public CLI consumes the same implementation. Platform bindings
will be public; they are not implemented by the temporary test bridges.

UI applications and server implementation can live separately. Their builds
must pin an identifiable public source revision or artifact digest, with valid
licensing rights. This repository must build without any private checkout,
private package registry, account credential or live service.

Current code implements byte profiles only. The following ports describe the
future boundary, not existing Rust traits or working endpoints:

| Port | Public policy | Host capability |
| --- | --- | --- |
| SyncTransport | Versioned protocol, validation, ordering, retry/deduplication and epoch handling | Bounded authenticated HTTP bytes, cancellation/deadline, typed failures |
| SessionProvider | No authentication secrets in document serialization | Obtain/clear transport authorization; never hand credentials to UI logs |
| SecureKeyStore | Key lifecycle, lock and key-version rules | OS-protected storage and availability notifications |
| EntropySource | Required fresh randomness, reject failure | OS CSPRNG or browser Web Crypto; no deterministic fallback |
| Storage/FileSystem | Atomic operations, commit boundaries, conflict/quarantine policy | Platform storage calls with explicit durability and failure semantics |

The CLI's platform adapters belong here. App adapters may live with the UI but
must not duplicate cryptography, conflict resolution or file policy. The server
authenticates users and enforces ownership, while encrypted content remains
opaque to it. Wire schemas/conformance fixtures are public; server controller,
database and deployment implementations are not prerequisites for public tests.

Open code is inspectable, not automatically trusted. Network/file input and host
callbacks are untrusted. The UI/OS can still observe plaintext, interfere with
entropy, or misrepresent what happened. This core does not defend against a
compromised client. FFI or a repository boundary is not a licensing exemption;
see [contribution and integration policy](../../CONTRIBUTING.md).
