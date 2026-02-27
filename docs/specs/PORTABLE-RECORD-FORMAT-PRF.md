# Portable Record Format (PRF)

Unified Specification v0.1

Status: Active  
Category: Informational + Standards-Track Profile  
Intended Use: Commercial record anchoring and decentralized registry infrastructure

Disclaimer: This specification reflects learnings from a current working implementation. It is an evolving document and may change without notice as operational and interoperability experience grows.

## Overview

This specification defines the Portable Record Format (PRF) as a foundation for a decentralized commercial registry.

Throughout commercial history, trade has depended on two enduring elements:

1. Recognizable documentary forms (charters, receipts, bills, certificates).
2. Shared methods of authentication (seal, signature, registry entry).

From the merchant houses of Florence and Venice to modern settlement systems, commerce advances when records are portable, verifiable, and recognizable across jurisdictions.

PRF extends that continuity into the digital era by binding widely accepted artifacts (for example JPG, PNG, PDF) to cryptographic integrity and verifiable authorship.

## Scope

Included:

- conceptual and structural definition of PRF
- relationship between document formats and cryptographic anchoring
- verification and interoperability rules
- decentralized registry implications and commercial effects

Not included:

- jurisdiction-specific legal advice
- monetary settlement mechanisms
- a mandatory transport network

## Design Premise

Any digital artifact may serve as a commercial record, provided its integrity, authorship, and continuity can be independently verified.

PRF does not replace established document formats. It anchors them.

## Core Structural Components

A Portable Record consists of:

1. Underlying artifact (for example contract PDF, image evidence JPG/PNG, statement).
2. Cryptographic anchor (digest, issuer key identity, signature, metadata).

The digest functions as a digital seal. Any alteration to the artifact invalidates integrity verification.

## Normative Core (v0.1)

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as described in RFC 2119.

### Supported Artifact Formats

At minimum, implementations MUST support:

- `image/jpeg`
- `image/png`
- `application/pdf`

Additional formats MAY be supported if deterministic digesting is possible.

### Portable Record Envelope

```txt
PortableRecord {
    id: string
    pubkey: string
    created_at: integer
    kind: integer
    tags: array<array<string>>
    content: string
    sig: string
}
```

This envelope is intentionally consistent with the Nostr NIP-01 event shape.

Field requirements:

- `id` MUST be 64 lowercase hex chars (32 bytes) and is the digest of canonical serialized event fields.
- `pubkey` MUST be 64 lowercase hex chars (32 bytes).
- `created_at` MUST be Unix timestamp (seconds).
- `kind` MUST be integer in range `0..65535`.
- `tags` MUST be arrays of one or more non-null strings.
- `content` is payload body (opaque text or canonical JSON profile).
- `sig` MUST be 128 lowercase hex chars (64 bytes).

### PRF Metadata in Tags

PRF metadata MUST be represented in tags.

Required exactly once for artifact-backed records:

- `["original_record_digest", "<alg>", "<digest>"]`
  - or extended form `["original_record_digest", "<alg>", "<mime>", "<digest>"]`
  - or legacy-minimal form `["original_record_digest", "<digest>"]` (fallback rules below)

Optional encrypted-storage companion digest:

- `["encrypted_record_digest", "<alg>", "<digest>"]`
  - or extended form `["encrypted_record_digest", "<alg>", "<mime>", "<digest>"]`
  - or legacy-minimal form `["encrypted_record_digest", "<digest>"]` (fallback rules below)

Optional:

- `["mime", "<mime>"]`
  - recommended when safe to disclose
  - omitted by default where MIME disclosure increases privacy or security exposure
- `["original_mime", "<mime>"]`
- `["encrypted_mime", "<mime>"]`

Optional examples:

- `size`
- `jurisdiction`
- repeatable `class`

Fallback and compatibility rules:

- If `original_record_digest` has 2 values (`tag`, `digest`), implementations SHOULD assume `SHA-256` as the digest algorithm.
- If `encrypted_record_digest` has 2 values (`tag`, `digest`), implementations SHOULD assume `SHA-256` as the digest algorithm.
- If both `mime` position in `original_record_digest` and standalone `mime` tag are absent, MIME MAY be inferred by implementation policy during retrieval/rendering.
- If MIME is withheld, `original_mime` and `encrypted_mime` MAY be omitted and inferred by implementation policy.
- Legacy split tags (`digest`/`alg`/`mime`) MAY be accepted for backward compatibility, but new records SHOULD emit `original_record_digest`.

### Canonicalization

Implementations MUST:

1. serialize deterministically using UTF-8
2. use canonical field order
3. avoid non-semantic whitespace

Under the NIP-01 binding profile, signing preimage MUST be UTF-8 JSON serialization of:

`[0, pubkey, created_at, kind, tags, content]`

Under the NIP-01 binding profile, escaping rules MUST match NIP-01 JSON expectations for control characters and quotes/backslashes.

### Signature Requirements

- Implementations MUST support at least one asymmetric signature algorithm.
- Under NIP-01 binding, implementations MUST use BIP-340 Schnorr over `secp256k1`.
- Signature validity MUST fail if any covered field changes.

### Verification Procedure

A PRF verifier MUST:

1. recompute `id` from canonical serialized event
2. verify `sig` against `pubkey`
3. extract `original_record_digest` metadata and validate required presence
4. resolve digest algorithm and digest value:
   - 4-field form: `tag, alg, mime, digest`
   - 3-field form: `tag, alg, digest`
   - 2-field form: `tag, digest` and default `alg=SHA-256`
5. obtain artifact and recompute digest using resolved `alg`
6. compare recomputed digest to resolved `digest`
7. when `encrypted_record_digest` is present, implementations SHOULD verify encrypted blob fixity against that digest before or during decrypt/retrieval workflows

Verification succeeds only if all checks pass.

No central registry is required for verification.

## Human Readability and Compact Encodings

PRF is intended to be independently inspectable by humans, including text-first command-line workflows used in operations and audit.

The canonical human-readable representation SHOULD use UTF-8 JSON.

Binary or compact machine-oriented encodings MAY be used for efficiency, provided verification semantics are unchanged.

When compact encodings are used, implementations MUST provide deterministic rendering into canonical human-readable UTF-8 JSON without loss of verification-critical fields.

Independent verifiers MUST be able to:

1. render compact/binary form into canonical readable form
2. recompute `id` and signature checks from that form
3. recompute artifact digest checks from required PRF tags

If deterministic rendering is not possible, the compact encoding is non-compliant for independent verification.

## Long-Term Archivability

PRF and the original artifact are intended to exist independently of any specific storage mechanism or media.

The objective is durable portability across archival environments and time horizons. A PRF record should remain transferable, interpretable, and independently verifiable after storage migration, export/import, and media refresh.

Implementations SHOULD favor:

- open, preservation-friendly artifact formats
- strong digest/fixity practices with independent verification
- structured preservation metadata for provenance and technical interpretation
- lifecycle management practices such as migration planning and renewal of integrity/signature evidence

PRF is storage-agnostic by design: verification invariants survive infrastructure change.

## Post-Quantum Agility

PRF intentionally starts with a simple baseline profile for ease of implementation and ecosystem adoption (NIP-01 envelope shape with current default signature conventions).

This simplicity is a deployment choice, not a long-term cryptographic limit.

PRF is designed to be algorithm-agile and can be extended through profile rules to support post-quantum primitives, including:

- ML-KEM for key establishment and payload protection workflows
- ML-DSA for quantum-resistant event signatures

Experimental implementations have already demonstrated feasibility for these algorithm families in event-based record systems.

To preserve interoperability, the baseline profile remains conservative today, while extension profiles MAY:

- introduce explicit algorithm signaling tags (for example signature/KEM identifiers)
- relax key/signature length assumptions where required by PQ schemes
- define verification dispatch rules based on declared algorithm profile

If an implementation does not support a declared PQ profile, it SHOULD fail closed for that record rather than silently downgrade verification semantics.

The specification therefore errs on the side of simplicity in the present, with a defined path to stronger post-quantum profiles as quantum threat relevance increases.

## Privacy and HNDL Considerations

PRF assumes artifact blobs may be harvested immediately by adversaries ("Harvest Now, Decrypt Later").

Accordingly:

- Integrity metadata is public and long-lived by design.
- Confidentiality MUST be provided by payload/blob encryption and key-management profiles, not by transport secrecy assumptions alone.
- Implementations SHOULD minimize metadata disclosure that is not required for verification.
- MIME disclosure is therefore OPTIONAL and can be carried in a separate `mime` tag only when needed.

This model supports long-term archival of encrypted blobs while preserving independent integrity verification under current and future cryptographic profiles.

Runtime and archival storage providers may also require encrypted-only content handling to avoid operational or legal implication in stored plaintext. PRF accommodates this by allowing both:

- `original_record_digest` for canonical/original artifact integrity
- `encrypted_record_digest` for encrypted-blob integrity at storage/runtime boundaries

In encrypted-only deployments, providers can validate `encrypted_record_digest` without needing plaintext access, while authorized parties can still verify `original_record_digest` after decryption.

## Registry Emergence

PRF does not require a centralized registry.

A decentralized registry may emerge when records are distributed, referenced by digest, and validated under shared rules.

## Cross-Jurisdictional Considerations

PRF relies on:

- recognized documentary formats
- cryptographic integrity
- digital signatures

PRF does not itself establish legal enforceability; legal effect remains jurisdiction-specific.

## Nostr Protocol Binding Addendum (NIP-01 Profile)

This addendum defines an optional binding profile.

Generalized envelope mapping:

- `record_id` -> `id`
- `issuer_id` -> `pubkey`
- `issued_at` -> `created_at`
- `record_type` -> `kind`
- `descriptors[]` -> `tags`
- `body` -> `content`
- `proof` -> `sig`

For NIP-01-bound PRF records:

- `original_record_digest` tag is REQUIRED and verification-critical
- `mime` is OPTIONAL
- both NIP-01 event verification and PRF artifact verification MUST pass

## Security Considerations

PRF is strongest when operators preserve:

- artifact immutability after digest/signature issuance
- clear key custody and rotation policies
- deterministic verification behavior across environments
- durable metadata retention for chain-of-custody review

## Implementation References

- [RECORD-PRESENTATION-NAUTH-STRATEGY.md](./RECORD-PRESENTATION-NAUTH-STRATEGY.md)
- [SAFEBOX-ALTERNATIVE-ECOSYSTEM-APPROACH.md](./SAFEBOX-ALTERNATIVE-ECOSYSTEM-APPROACH.md)
- [HISTORICAL-CONTEXT-LAW-MERCHANT-AND-DIGITAL-EXCHANGE.md](./HISTORICAL-CONTEXT-LAW-MERCHANT-AND-DIGITAL-EXCHANGE.md)
- [TRANSPORT-SECURITY-AND-HYBRID-ADDRESSING.md](./TRANSPORT-SECURITY-AND-HYBRID-ADDRESSING.md)
