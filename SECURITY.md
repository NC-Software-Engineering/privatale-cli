# Security policy

This is an experimental, synthetic-data cryptography prototype. No production
release or supported journal client is available. Do not use it to protect real
journals yet. A reproducible test suite is evidence about its assertions, not an
independent security audit, certification or proof of complete key management.

## Reporting

Report vulnerabilities privately through
[GitHub vulnerability reporting](https://github.com/NC-Software-Engineering/privatale-cli/security/advisories/new).
The repository administrator must enable and verify that channel before the
first code publication. If unavailable, use an already established private
channel with the maintainer; do not put secrets or exploit details in public
issues. No response-time or bounty commitment is made at this stage.

Include affected revision, synthetic reproduction, expected/observed behavior
and impact. Never attach personal journals, account credentials, recovery keys
or unredacted memory dumps. Maintainers coordinate a fix and disclosure, assess
affected versions and publish an advisory when appropriate. Secret exposure
requires revocation/rotation by the owner; deleting a Git commit is insufficient.

## Threat and implementation limits

- Network messages, file contents and host callbacks are untrusted. Crypto
  authenticates bytes; it does not authenticate a compromised UI or OS.
- Base HPKE does not authenticate a sender. Enrollment/trust, replay/epoch
  semantics, storage, revocation and sync authorization are not implemented.
- Stream prefixes must not be treated as completed files. The caller must wait
  for successful `finish` before committing a complete object.
- Linux wrappers use fallible OS entropy; browser wrappers use Web Crypto.
  Deterministic fixture APIs are not safe defaults for application encryption.
- Explicit zeroization does not guarantee erasure of compiler, library, JS GC,
  OS swap, debugger or caller copies. No locked-memory agent exists yet.
- CI uses synthetic data only. Raw scanner reports and browser profiles are not
  public artifacts. Dependency advisories are checked separately from vectors.

See [byte profiles](docs/protocol/crypto-v1.md),
[boundaries](docs/architecture/boundaries.md) and
[verification](docs/security/verification.md).
