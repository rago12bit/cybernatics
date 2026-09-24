# ADR-005: No blockchain for report integrity; Sigstore, in-toto and RFC 3161 instead

Status: Accepted (2026-09-25)

## Context
The original concept included a blockchain to make scan reports tamper-evident. The real
requirements are narrower: a reader must be able to verify that (1) a report was produced by this
system, (2) it was not modified afterwards, and (3) it existed at a given time.

## Options considered
1. **Public or private blockchain / distributed ledger.** Stores a hash on-chain.
2. **Sigstore (cosign) signatures + in-toto attestations + RFC 3161 timestamps.**
3. Do nothing (plain files).

## Decision
Option 2, scheduled for Phase 5. Reports are signed with cosign, wrapped in an in-toto attestation
describing the inputs (source digest, scanner image digests, tool versions) and timestamped by an
RFC 3161 authority.

## Why not a blockchain
- It provides no property this system needs that signatures and timestamps do not: integrity comes
  from the hash and signature; time comes from the timestamp authority; provenance comes from the
  attestation. A ledger adds a fourth mechanism for a problem already solved by the first three.
- Consensus, immutability and decentralisation are valuable when parties distrust one another.
  Here one operator produces reports for its own users; there is no adversarial multi-party write.
- It adds operational cost (nodes, fees or a private network), latency and a new attack surface to
  a system whose whole job is to reduce attack surface.
- The industry already uses Sigstore, in-toto and timestamping for exactly this: verifiable
  software supply-chain artifacts. Tooling, verifiers and auditors already exist.

## Consequences
- Verification works offline with standard tools (`cosign verify-blob`, `in-toto-verify`).
- If a future requirement genuinely needs multi-party, publicly auditable history (for example a
  transparency log across organisations), Sigstore's Rekor transparency log already provides an
  append-only, publicly verifiable log without introducing a blockchain.
- This decision is reversible; reversing it should be a deliberate, documented act.
