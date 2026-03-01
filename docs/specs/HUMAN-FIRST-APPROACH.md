# Human-First Approach

## Overview

Safebox is designed first to preserve human agency in digital exchange: a person should be able to understand, initiate, approve, and verify critical actions without surrendering control to opaque intermediaries.

This is a sequencing and governance principle, not a rejection of automation.

## Core Principle

Primary principle:

- preserve human agency as the baseline trust boundary.

Extension principle:

- there is no practical reason this principle cannot be extended to agents acting on behalf of humans, provided those agents operate under explicit delegated scope, auditable controls, and revocable authority.

In Safebox terms, human and agent paths should converge on the same security semantics, request/response contracts, and verification outcomes.

### Human-Agent Flow Parity Principle

Safebox adopts a strict flow-parity principle:

- any capability available to a human-operated Safebox SHOULD have an agent-operable path with equivalent security semantics;
- any capability available to an agent-operated Safebox SHOULD remain interoperable with human-operated Safeboxes without protocol forks;
- interaction direction SHOULD be symmetric where feasible: human-to-human, human-to-agent, agent-to-human, and agent-to-agent paths should rely on the same core handshake and verification contracts.

This principle exists to prevent split ecosystems, reduce integration fragility, and keep one auditable protocol surface across UI and API operation.

## Delivery Sequence

Safebox development follows a deliberate sequence:

1. Harden human-operated flows first (QR, NFC, browser/mobile interaction).
2. Align agent-operated flows to the same protocol contracts and behavioral guarantees.
3. Preserve cross-mode interoperability so human-controlled and agent-controlled wallets can interact without protocol forks.

This approach reduces regression risk and keeps automation grounded in proven human-path behavior.

## Bootstrapping Channel Strategy

### QR as Primary Bootstrap Interface

QR codes are the primary interface for bootstrapping interactions across:

- human-to-human
- human-to-agent
- device-to-device workflows where a visual out-of-band handshake is practical

QR is used for handshake coordination, not bulk sensitive transfer.

### Bech32 for Robust Transport Encoding

For agent/backend and constrained-channel exchange, Safebox uses bech32-oriented encodings (for example `nauth`/`nembed`) because checksum-bearing payloads are more resilient in noisy or adversarial channels.

This is especially important for bootstrap steps where transcription errors, partial scans, relay ambiguity, or hostile injection attempts can break flow safety.

## Minimal Bootstrap Data Policy

A strict policy applies to bootstrap payloads (especially QR-visible material):

- carry handshake parameters only
- avoid embedding sensitive business payloads
- avoid including metadata that materially increases inference risk

Handshake parameters may include scoped authorization context, nonce/correlation values, transport hints, and algorithm/profile identifiers required to establish a secure follow-on channel.

Nonce values are mandatory for bootstrap session correlation and replay resistance. In unreliable or insecure channels, nonce-bound handshakes are a primary control against session hijacking and cross-session message injection.

Sensitive records and high-value payload content are transferred only after channel establishment, using protected transport and envelope controls.

## Human and Agent Consistency Goals

Safebox aims for protocol-level consistency across human and agent operation:

- same authorization semantics
- same verification rules
- same failure and fail-closed behavior
- same auditability expectations

Agents should not receive weaker guarantees or privileged bypasses relative to human-operated flows.

## Bounded Delegation and Key Continuity

A Safebox instance, whether controlled directly by a human or operated by an agent, is intended to act as a bounded delegate.

Delegation properties:

- authority is scoped
- authority can be revoked or rotated on short notice
- compromise of one delegate key should not imply permanent loss of owner authority

Record continuity properties:

- previously issued public records may remain valid as historical attestations
- owner continuity can be re-established by attesting from a new owner-controlled key
- key rotation changes present authority, not necessarily the historical validity of already published attestations

This allows rapid operational containment (revoke/rotate) while preserving evidentiary continuity where public records are required.

### Private Records and Persistence Independence

Safebox instances can also issue private records whose long-term validity does not depend on continued existence of that specific Safebox instance.

Private record model:

- private records follow the PRF-style anchor model (artifact + cryptographic traceability metadata)
- issuance-time control is attributable to the owner controlling the Safebox at that moment
- traceability/accountability is preserved cryptographically even if the originating Safebox instance is later rotated, revoked, or decommissioned

Therefore, long-term recognition depends on cryptographic traceability to the owning entity (human and/or legal entity) that initiated the flow, not on runtime persistence of the original service component.

This separation clarifies:

- what is cryptographically necessary to establish evidence and continuity, versus
- what legal frameworks may require to assign or recognize legal effect.

## Security and Governance Posture

Human-first does not mean anti-agent. It means:

- humans remain the root of authority
- agents are bounded delegates
- protocol behavior remains neutral and verifiable
- institutional controls (policy/compliance/enforcement) operate at governance boundaries, not by weakening protocol invariants

## Protocol Neutrality and Higher-Order Controls

Safebox is agent-ready by design because the protocol treats humans and agents alike at the base layer:

- same identity model (`npub`-anchored actors)
- same cryptographic and flow contracts
- same revocation/rotation semantics for delegated components

Safebox itself is not intended to be the universal policy enforcer for institutional controls such as KYC/AML eligibility decisions. Those controls belong to higher layers (operators, regulated institutions, and policy overlays) where legal mandate, jurisdiction, and governance context are defined.

Practical implication:

- Safebox does not implement a global protocol-level ban list for `npub` identities.
- legitimacy and reputation are established through higher-order controls (trust policy, attestations, institutional onboarding, and risk systems), not by base-protocol discrimination.

Analogy: the Internet does not globally "ban" an IP address as a protocol primitive for suspected misuse in every context; network and service operators apply policy at higher layers. Safebox applies the same separation of concerns for `npub`-based operation.

## Implementation References

- [SAFEBOX-ALTERNATIVE-ECOSYSTEM-APPROACH.md](./SAFEBOX-ALTERNATIVE-ECOSYSTEM-APPROACH.md)
- [AGENT-FLOWS.md](./AGENT-FLOWS.md)
- [OFFERS-AND-GRANTS-FLOWS.md](./OFFERS-AND-GRANTS-FLOWS.md)
- [RECORD-PRESENTATION-NAUTH-STRATEGY.md](./RECORD-PRESENTATION-NAUTH-STRATEGY.md)
- [NEMBED-PROTOCOL.md](./NEMBED-PROTOCOL.md)
- [NAUTH-PROTOCOL.md](./NAUTH-PROTOCOL.md)
