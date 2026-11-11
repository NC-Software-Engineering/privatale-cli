# Contributing

Start with [README](README.md), [SECURITY](SECURITY.md) and the
[protocol profiles](docs/protocol/crypto-v1.md). Run the complete native,
WASM/Node, independent-oracle and real-browser checks before proposing a change.
Formatting, clippy, public-source checks and secret/advisory/license checks must
also pass. Linux is the current verification target; other platforms are future
work, not implied support from a successful WASM build.

Keep changes focused. Protocol bytes, limits, KDF contexts and parameters need
explicit versioning/security review and cross-runtime negative tests. Do not
regenerate golden fixtures merely to make a failed implementation pass. Record
independent provenance and reproduce vectors with the separate Python oracle.
Dependency updates are separate, deliberate changes to the lockfile and review.

All examples use synthetic data. Never commit credentials, actual diary content,
private service configuration, personal workstation paths, generated binaries or
raw runtime evidence. Install the local pre-commit hook after bootstrapping the
pinned tools; CI repeats checks because hooks can be bypassed.

## Licensing and application integration

The public project is offered under AGPL-3.0-only. Preserve the full standard
source header shown in README and all third-party notices. JSON/CSV data use
license sidecars so their tested bytes are unchanged. A file's presence here
does not grant rights beyond its applicable license.

The intended model is public AGPL code with separately established rights for
the copyright holder's proprietary clients. A separate repository, WASM or FFI
does not itself establish those rights. The owner must verify ownership and
permissions before distributing a proprietary integration.

External code contributions are not accepted for merging until a reviewed
contributor agreement and process supporting that model are in place. A DCO or
ordinary AGPL contribution does not automatically grant alternative licensing
rights. This document does not ask contributors to assign rights implicitly or
claim that such an agreement already exists. Discussion and synthetic bug
reports are welcome; vulnerabilities follow SECURITY.md.
