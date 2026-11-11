# Synchronization boundary (not implemented)

The intended service prefix is `/sync/v1`. No HTTP endpoint, request/response
schema, transport client, durable queue or server is implemented in this import.
`sync_item_v1` is a cryptographic envelope profile, not a sync implementation.

Before implementing transport, publish a versioned wire contract covering:

- Push/pull requests, bounded encrypted items, cursor/sequence representation,
  retries, idempotency, ordering, cancellation and typed errors.
- Authenticated ownership and device/key epochs; revocation and stale-client
  behavior; snapshots and compaction without silently losing offline changes.
- Inline versus blob references, authenticated metadata and full-stream commit.
- Public synthetic fixtures and a self-contained mock/conformance runner. Private
  server tests must consume the same contract, without exporting server code or
  operational configuration.

The client must verify authenticated envelopes before applying content. A blob
prefix is not a complete file: `Reader::finish` must succeed before a caller
commits the complete object. Server acceptance alone is not crypto verification.
Session credentials belong to transport/OS capabilities, not serialized journals
or diagnostic logs. No deployment hostname, OAuth secret or production dataset
is necessary to specify or test this boundary.
