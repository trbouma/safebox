# Safebox Alternative Ecosystem Approach

## Overview

This document describes Safebox as an alternative approach to state-centric
digital identity wallet ecosystems.

For foundational context on artifact-plus-anchor records and decentralized
registry semantics, see:

- [Portable Record Format (PRF)](./PORTABLE-RECORD-FORMAT-PRF.md)

Safebox targets the same high-level outcomes:

- user-controlled credential and payment interactions
- selective data sharing
- verifier-requested proof/presentation
- interoperable transport and verification patterns

Safebox differs in architecture and trust model:

- protocol-first and network-native (Nostr, Cashu, Lightning, NIP-17 style messaging)
- operator-pluggable trust boundaries (relay, mint, blob storage)
- key-centric sovereignty where user key control is foundational
- practical resilience under unreliable and mixed environments (browser/mobile/NFC/QR/cross-instance)

## Scope

This specification covers:

- Safebox role model and trust boundaries
- issuance/presentation/payment equivalents to common verifier ecosystems
- credential and record transfer mechanics
- security and resiliency posture
- operational and interoperability implications

This specification does not define national identity conformance requirements.

## Big-Picture Architecture

Safebox ecosystem roles map as:

- Holder Wallet: user-controlled key material and local wallet state
- Service Operator: deploys Safebox instance(s), relays, mint routing, blob backends
- Record/Credential Issuer: any actor issuing signed records/events
- Verifier/Relying Party: entity requesting proof/record presentation
- Relay Network: asynchronous message transport and event discovery
- Mint Layer: ecash issuance/redemption/payment settlement
- Blob Storage Layer: encrypted original-document storage and transfer

Core channels:

- QR / NFC as bootstrap and authorization channels
- relay-based secure transmittal for payload exchange
- wallet APIs (human UI and agent API) for orchestration

## Protocol and Format Strategy

Safebox uses a modular envelope strategy rather than a single mandatory
credential format stack.

- `nauth`: authentication/transmittal intent envelope
- `nembed`: compact transport envelope for NFC/QR/message constraints
- signed Nostr events for records/attestations
- encrypted payload wrapping for sensitive transfer content
- optional PQC KEM for quantum-safe shared-secret derivation

Design principle:

- QR/NFC carry minimal bootstrap material
- sensitive content is transferred over negotiated secure channels

## Why Safebox Uses `nAuth` Instead of OAuth/OID Core Flows

Safebox intentionally does not use OAuth 2.0, OID4VCI, or OID4VP as the core
security primitive for wallet-to-wallet sensitive payload exchange.

Reasoning:

- OAuth-style bearer semantics are possession-based:
  - whoever holds the token can often use it
  - server-side systems cannot always prove cryptographic holder binding
- OAuth/OID ecosystems are operationally complex:
  - multiple redirect/token/introspection/state paths
  - uneven implementation quality across providers
  - difficult end-to-end security auditing in heterogeneous deployments
- Transport-layer trust (TLS) is necessary but insufficient:
  - real deployments terminate TLS at proxies, load balancers, and gateways
  - sensitive artifacts can leak into logs/headers/intermediate systems
  - this is hop-by-hop protection, not payload-carried end-to-end guarantees

Safebox design choice:

- move security emphasis from pipe security to payload security
- bind request/response context with `nauth` (nonce/scope/relay/kind constraints)
- use explicit cryptographic proof paths and encrypted payload envelopes
- support optional PQC KEM for stronger forward-looking protection

In short, Safebox treats OAuth/OID patterns as useful compatibility tooling in
broader ecosystems, but not as sufficient long-term primitives for sovereign,
adversarially aware, decentralized wallet exchange.

### Transitional Position

This is not a claim that OAuth/OID must be abandoned everywhere immediately.
They remain practical in many existing infrastructures. Safebox’s position is:

- acceptable for integration bridges where required
- not preferred as the foundational trust mechanism for core private payload
  exchange
- long-term direction should favor cryptographic holder/request binding with
  payload-level confidentiality and verifiability

## Issuance and Presentation Model

Safebox has two dominant interaction families:

- Offer/Grant flow (issuer-like push model)
- Request/Present flow (verifier-like pull model)

Both operate over:

- QR
- NFC
- agent-driven API flow (recipient-first support)

Behavioral equivalent to issuance/verification ecosystems:

- user consent and claim scope are explicit in flow context
- response is bound to request context (`nauth`, nonce, relay/kind scope)
- verifier receives only what is explicitly presented

## Trust Model: Central Registry vs Operator-Scoped Trust

Safebox does not require a single global trust list authority. Trust is formed by:

- signature validation of record events
- relay-sourced event integrity checks
- configurable issuer/verifier acceptance policies
- optional operator/community governance overlays

Implication:

- lower central dependency
- greater operator responsibility for policy, abuse handling, and compliance

## Holder and Request Binding

Safebox implements holder/request binding through combined controls:

- key possession proofs (wallet private key / derived transfer keys)
- nonce-bound request correlation
- scoped relay and transmittal-kind constraints
- optional PQC KEM handshake for encrypted payload/key exchange

Hardening posture:

- missing/invalid cryptographic materials must fail closed where required
- malformed legacy/partial payload cases degrade safely without crashing flow

### Holder Binding in Wallet-to-Wallet Grant Flows

In Safebox grant exchange, holder binding is explicit at issuance time:

- the sending wallet (acting as issuer for the grant event) knows the recipient
  wallet identity as `npub`
- the issued grant/transmittal is constructed for that recipient identity
- secure transmittal is routed and encrypted for that recipient context

At presentation/acceptance time, the receiving wallet returns proof-bearing
messages over secure protocols that are also tied to `npub` identities and
request context (`nauth`, nonce, relay/kind scope).

Result:

- grants are not treated as anonymous bearer artifacts
- issuer intent and recipient identity are cryptographically and protocol-bound
  through wallet keys and scoped transmittal state

## Revocation and Status Perspective

Safebox status checks are not tied to a single mandatory revocation registry
format. Status is represented through:

- current relay-observable state/events
- operator-side policy checks
- token/record lifecycle controls in application logic

This is flexible but requires explicit governance policy if formal revocation
semantics are needed for regulated contexts.

## Interoperability Profile Approach

Safebox favors profile-by-configuration:

- relay set configuration
- transmittal kind defaults and overrides
- mint and payout behavior
- blob home/xfer separation and fallback policy

Equivalent of a strict interoperability profile is achieved operationally by:

- deployment baselines
- cross-instance sanity checks
- protocol hardening specs and test plans

## Security and Resiliency Differences

Safebox emphasizes hostile-network resilience and asynchronous reliability:

- listener-first sequencing where race-prone
- stale-record filtering for relay history ambiguity
- fallback hierarchy for blob retrieval (`xfer -> home -> graceful missing`)
- non-fatal cleanup/delete where backend capabilities differ
- multi-relay publish/listen patterns to reduce single-relay failure risk

Operationally, this trades deterministic central orchestration for resilient
distributed behavior under partial failures.

## Privacy and Data-Minimization Posture

Safebox privacy model centers on:

- selective presentation by flow scope
- encrypted blob storage/transfer
- minimal bootstrap data on QR/NFC edge channels
- user key custody as primary security boundary

System-level privacy guarantees depend on deployment choices:

- relay selection
- storage providers
- operator logging and retention policy

## Compliance and Governance Considerations

Safebox can be run in regulated environments, but compliance is not inherited
from a central accreditation fabric by default.

Required operator controls include:

- legal process handling and audit readiness
- policy enforcement for prohibited use
- retention/deletion governance
- evidence and incident response procedures

## Practical Positioning

Safebox is best characterized as:

- a sovereign, composable wallet-and-records ecosystem
- optimized for real-world constraints (mixed devices, cross-instance operation, intermittent infrastructure)
- compatible with progressive hardening and policy layering over time

It is not a drop-in replacement for jurisdiction-specific assurance schemes,
but a technically robust alternative architecture for communities and operators
that prioritize user control and protocol-level openness.

## Implementation References

- `app/routers/records.py`
- `app/routers/safebox.py`
- `app/nwc.py`
- `safebox/acorn.py`
- `docs/specs/NAUTH-PROTOCOL.md`
- [Portable Record Format (PRF)](./PORTABLE-RECORD-FORMAT-PRF.md)
- `docs/specs/NEMBED-PROTOCOL.md`
- `docs/specs/OFFERS-AND-GRANTS-FLOWS.md`
- `docs/specs/NFC-FLOWS-AND-SECURITY.md`
- `docs/specs/ACORN-RESILIENCY-AND-GUARDS.md`
