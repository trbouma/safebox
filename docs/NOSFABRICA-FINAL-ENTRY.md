# Nosfabrica Final Entry

Reference:
- [Nosfabrica Hackathon Proposal](NOSFABRICA-PROPOSAL.md)
- [Acceptance Model](specs/ACCEPTANCE-MODEL.md)
- [WoT, Attestation, and Record Verification](specs/WOT-ATTESTATION-AND-RECORD-VERIFICATION.md)
- [Issued-to-Holder Presentation Profile](specs/ISSUED-TO-HOLDER-PRESENTATION-PROFILE.md)
- [Progress Report 2026-04](PROGRESS-REPORT-2026-04.md)

Date: 2026-04-08

Status: Implemented and Demonstrable

## Purpose

This document serves as a final-entry summary for the Nosfabrica proposal. It describes what has now been implemented in Safebox, what can be demonstrated live, and how the delivered work relates back to the proposal goal of extending the Web of Trust through the Acceptance Model.

## Proposal Goal

The proposal set out to demonstrate that Safebox could support the issuance, secure exchange, presentation, and independent verification of private records in a decentralized environment.

The core target scenario was:

- one Safebox issues a private record to another Safebox
- the holder receives and stores the record
- the holder later presents the record to another participant
- the verifier independently evaluates the record based on:
  - cryptographic validity
  - owner attestation
  - Web of Trust standing
  - reputation-style trust signals where available

The proposal used the health-record and prescription use case to drive requirements, but the resulting implementation is now generic enough to support broader issued-to-holder and verifier-local trust workflows.

## Summary of What Has Been Implemented

### 1. Acceptance Model and trust architecture

Safebox now includes a more explicit trust and verification framework based on the Acceptance Model.

Implemented:
- a staged model distinguishing:
  - validation
  - verification
  - attestation
  - recognition / authorization
  - trusted assertions
  - acceptance
- documentation explaining how claims become actionable system facts
- explicit treatment of verifier-local stop conditions
- identity-neutral treatment of `npub` actors, whether human, agent, service, device, or Safebox instance

Supporting docs:
- [Acceptance Model](specs/ACCEPTANCE-MODEL.md)
- [Issued-to-Holder Presentation Profile](specs/ISSUED-TO-HOLDER-PRESENTATION-PROFILE.md)

### 2. Private record issuance

Safebox can now issue private records from one user to another in a structured, tagged format.

Implemented:
- issuance of private records with explicit tags for:
  - issuing safebox
  - safebox owner
  - safebox holder
- grant generation from offers
- request generation from grants
- support for original-record blob transfer when applicable

This means a record can now carry both issuance provenance and holder-binding information in a way that can later be evaluated by a verifier.

### 3. Secure record exchange

The proposal built on earlier secure direct sharing work and required that record exchange be extended for verifiable private records.

Implemented:
- QR-based and recipient-initiated offer/request flows
- cross-instance offer and request handling
- websocket-based exchange flows
- secure transmittal using existing Safebox record transport patterns
- quantum-safe / KEM-aware paths for mixed deployments
- improved nonce handling, request binding, and replay protections in the exchange path

This is now demonstrable across Safebox instances rather than being confined to same-instance testing only.

### 4. Owner attestation

The proposal explicitly called for records to be verifiable not only by signature validity, but also by whether the issuing safebox is under the control of the stated owner.

Implemented:
- owner attestation via kind `31871`
- use of deterministic tags of the form:
  - `<safebox npub>:safebox-under-control`
- publishing and lookup of owner-control attestations
- record verification logic that evaluates whether the record owner has attested control of the issuing Safebox

This is now integrated into the record verification pipeline as:
- `Attested By Owner`

### 5. Web of Trust recognition

The proposal called for independent standing and trust evaluation rather than centralized authority.

Implemented:
- verifier-managed root authority lists
- trust expansion from configured roots
- recognized-issuer evaluation using verifier-local trust configuration
- provenance display showing which root authorities recognized the issuer

This is now integrated into the record verification pipeline as:
- `Recognized`
- `Recognized By`

The important property here is that recognition is local to the verifier. Safebox does not assume global authority. Each verifier decides which roots and trust relationships matter.

### 6. Trusted assertions and advisory reputation signals

The proposal referenced NIP-85 Trusted Assertions as a way to handle scalable reputation-style trust input.

Implemented:
- trusted assertion provider configuration
- support for provider entries of the form:
  - `npub:tag[:relay]`
- WoT score lookup during record verification
- explicit fallback behavior such as:
  - `rank: na`

This is now integrated into verification output as advisory trust information rather than a mandatory gate.

### 7. Shared record verification engine

One major implementation step was the consolidation of record verification logic into a shared verification module.

Implemented:
- shared verification helpers for:
  - payload parsing
  - owner normalization
  - attestation lookup
  - trust recognition
  - root-recognition provenance
  - WoT score retrieval
  - holder / presenter semantics
- request-scoped caching for repeated trust lookups
- consistent verification rendering across:
  - request flows
  - grant display
  - single-record views
  - my-records views

This has made the verification model much more inspectable, consistent, and easier to demonstrate.

### 8. Holder and presenter semantics

The proposal’s prescription scenario depends on being able to distinguish issuer, holder, and verifier clearly.

Implemented:
- record tags for `safebox_holder`
- `Self-Presented` logic in live request / presentation flows
- `Held By Current Safebox` logic for stored-record views
- a generic issued-to-holder presentation profile describing minimum acceptance rules

This allows a verifier to distinguish:
- who issued the record
- who owns the issuing Safebox
- who the record was issued to
- whether the current presenter is the intended holder

## What Is Demonstrable

The following is now demonstrable in the repository and running Safebox environments.

### Demonstration 1. Issued-to-holder verification flow

Live flow:
- an issuer Safebox issues a private record to a holder Safebox
- the holder receives and stores the record
- the holder presents the record to a verifier
- the verifier sees a verification panel showing:
  - `Valid`
  - `Attested By Owner`
  - `Recognized`
  - `Recognized By`
  - `Issuer WoT Scores`
  - `Self-Presented` in live presentation flows

This directly satisfies the core architectural goal of the proposal.

### Demonstration 2. Verifier-local Web of Trust

Live flow:
- a verifier configures root authorities and trusted assertion providers
- the same record is evaluated under that verifier’s trust context
- recognition and score signals appear only when the verifier has chosen the relevant trust anchors

This demonstrates the proposal’s central idea that trust is not globally imposed but is rooted in independently configured points of view.

### Demonstration 3. Owner-control attestation

Live flow:
- an owner publishes a `31871` safebox-under-control attestation
- the issuing Safebox uses that owner identity when publishing grants
- a verifier can independently resolve whether the record owner has attested control of the issuing Safebox

This demonstrates a key proposal requirement: a verifier does not merely trust a label, but can inspect whether the owner-identity relationship is actually attested.

### Demonstration 4. Cross-instance record exchange

Live flow:
- one Safebox instance issues or offers a record to another instance
- the record is received and later presented
- verifier-side verification still works across instances

This demonstrates that the solution is not only same-instance or same-operator dependent.

## Relation to the Health / Prescription Use Case

The health-record framing in the proposal has served its purpose: it drove out concrete requirements for a more general decentralized record issuance and verification capability.

What is now in place is sufficient to model the generic structure of the prescription scenario:

- issuer:
  - doctor or other authoritative actor
- holder:
  - patient or end-user
- verifier:
  - pharmacist, clinic, provider, or other relying party

The system can now support the following checks:
- the record is cryptographically valid
- the owner has attested control of the issuing Safebox
- the issuer / owner is recognized by the verifier’s configured root authority list
- the verifier may also consult advisory WoT or reputation signals
- the presenter can be evaluated against the intended holder in live presentation flows

While the current implementation remains generic rather than verticalized for healthcare policy, it now provides the core decentralized issuance and verification building blocks that the proposal set out to prove.

## Important Delivered Properties

The implementation now makes the following properties real and inspectable:

- there is no protocol-level distinction between humans, agents, services, devices, and Safebox instances
- records are not treated as facts because a platform says so
- trust is verifier-local
- attestation and recognition are separated
- trusted assertions remain advisory rather than silently overriding validity or ownership
- acceptance is explicit and programmable rather than hidden

These are not just ideas in the documentation. They are now reflected in the verification logic and UI.

## What Remains In Progress

Although the proposal goals have been substantially implemented, some areas remain active engineering work rather than final closure.

These include:
- continued hardening of long-lived Cashu proof lifecycle handling
- continued simplification of some complex cross-instance and asynchronous flows
- broader end-to-end regression coverage
- deeper policy profiles for vertical use cases such as healthcare, licensing, or institutional registries

These are now best understood as product-hardening work on top of a delivered architecture, rather than missing core capabilities.

## Final Assessment

The Nosfabrica proposal has now been substantially implemented.

Safebox demonstrably supports:
- private record issuance
- issued-to-holder record transfer
- presentation to a verifier
- owner-control attestation
- verifier-local Web of Trust recognition
- advisory trusted assertions
- explicit verification output grounded in the Acceptance Model

The original goal was to show that decentralized systems can move from raw claims to accepted, actionable outcomes without centralized gatekeepers. Safebox now demonstrates that in working code, operator workflows, and live verification flows.

The proposal’s health-record framing remains important, but the resulting implementation is broader: it now provides a generic decentralized issuance, presentation, and trust-evaluation model that can be applied well beyond the initial prescription example.
