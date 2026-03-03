# ToIP Architecture And Implementation Considerations
**Status**: Draft  
**Date**: 2026-03-03  
**Audience**: Safebox engineering, agent-runtime maintainers, protocol/spec authors

---

## 1. Purpose

This document maps Trust over IP (ToIP) trust-layer concepts to the Safebox agent ecosystem and defines pragmatic implementation guidance.

It is intended to:

- align Safebox Agent API and market specs with durable trust principles,
- identify gaps between current capabilities and ToIP-style requirements,
- prioritize near-term implementation steps without blocking current product velocity.

This document is architecture guidance. It does not replace endpoint-level behavior defined in:

- `docs/specs/AGENT-API.md`
- `docs/specs/AGENT-FLOWS.md`
- `docs/specs/mkt/MS-01-coupon-market.md`

---

## 2. Scope

### In scope

- Agent identity continuity and portability
- Authentication and delegated authorization patterns
- Data authenticity and provenance for agent actions
- Trust/audit evidence model for market workflows
- Incremental implementation roadmap for Safebox

### Out of scope

- Full adoption of any specific external ToIP profile
- Legal/trust-framework governance agreements
- Replacement of Nostr/Lightning primitives currently used by Safebox

---

## 3. Current Safebox Trust Baseline

Safebox already has strong trust primitives:

- wallet-level cryptographic identity (Nostr key material),
- signed event model for public actions (kind-1/7/etc),
- encrypted direct messaging (gift-wrap transport),
- settlement rails via Lightning and ecash flows,
- policy and conformance trend in market specs (MS-01).

Current limitations are primarily composition-layer concerns:

- delegation chains are implicit rather than explicitly verifiable,
- provenance is distributed across events/logs rather than normalized evidence,
- trust decisions are policy-driven but not uniformly cryptographically bound per step.

---

## 4. ToIP-Aligned Reference Architecture

## 4.1 Layer Model

### Layer A: Identity Layer

Defines long-lived agent identifiers and key lifecycle:

- stable agent identifier,
- key rotation policy with continuity,
- binding between operational handles (`nip05`, `lud16`) and cryptographic identity.

### Layer B: Trust Messaging Layer

Defines authenticated, tamper-evident messages between principals:

- message-level signature and sender binding,
- replay controls (nonce, timestamp window, idempotency key),
- verification context retained with each message artifact.

### Layer C: Delegation Layer

Defines who authorized what, at which scope, for which duration:

- principal chain (human/operator -> orchestrator -> execution agent),
- operation-scoped delegation claims,
- revocation and expiry rules.

### Layer D: Application Protocol Layer

Safebox-specific workflows:

- `/agent/*` API flows,
- DM/zap market loops,
- MS-01 order lifecycle.

### Layer E: Evidence/Audit Layer

Standardized, queryable evidence for decisions and settlement:

- action envelope + verification results,
- policy decision + reason,
- outcome references (event ids, tx ids, dm ids).

---

## 5. Target Trust Properties

Implementations should trend toward these properties:

1. Durable identity continuity  
Agent identity survives process, host, and provider migration.

2. Message authenticity independent of transport  
Evidence remains verifiable after data leaves the original session.

3. Explicit delegated authorization  
Each sensitive action can be tied to a delegation chain and scope.

4. Deterministic provenance  
Any observer can reconstruct why a market action was accepted or rejected.

5. Revocation and expiry enforceability  
Expired authority and stale orders are rejected by default.

---

## 6. Gap Analysis: Safebox vs ToIP-Oriented Model

## 6.1 Identity

Strengths:

- Nostr-native key material and signed events are already present.

Gaps:

- no explicit identity continuity profile for key rotation,
- no formal “agent identity document” linking keys, handles, and lifecycle status.

## 6.2 Authentication and Delegation

Strengths:

- `X-Access-Key` model is operationally simple.

Gaps:

- bearer-style auth does not express delegation chain,
- operation scope and issuer context are not first-class claims.

## 6.3 Data Authenticity and Provenance

Strengths:

- signed public events and zap receipts provide strong anchors.

Gaps:

- cross-step provenance is implicit and fragmented,
- no single normalized verification envelope for agent decisions.

## 6.4 Market Integrity

Strengths:

- MS-01 now includes anti-self-trade and conformance rules.

Gaps:

- fill/reject rationale not yet standardized as machine-readable evidence objects.

---

## 7. Implementation Considerations

## 7.1 Identity Continuity Profile

Add an internal profile for each agent wallet:

- `agent_id` (stable logical identifier),
- `current_npub` + rotation history,
- `nip05`/`lud16` binding status,
- profile completeness state (`INCOMPLETE_PROFILE_SETUP`, etc.).

Recommended:

- require immediate post-onboard bootstrap:
  - custom handle claim,
  - kind-0 publish with `name`, `picture`, `nip05`, `lud16`,
  - `nip05 == lud16` for managed identities.

## 7.2 Delegation Envelope (Incremental)

For sensitive operations (`zap`, `pay_invoice`, `pay_lightning_address`, market fill), add optional request metadata:

- `delegation_id`
- `delegator` identifier
- `scope` (`market.fill`, `dm.send`, `payment.zap`, etc.)
- `expires_at`
- `nonce`

Server should:

- verify expiry and nonce uniqueness,
- persist delegation metadata with action evidence.

## 7.3 Provenance Envelope

For each executed agent action, persist a structured evidence object:

- actor identity (`npub`, handle),
- target references (event id, order id, recipient),
- validation outcomes (amount match, event match, policy checks),
- decision (`accepted`/`rejected`) + reason code,
- resulting artifacts (tx id, dm id, reply event id).

This should be queryable for conformance and incident analysis.

## 7.4 Idempotency and Replay Safety

Require idempotency keys for settlement-sensitive paths:

- recommended key shape:
  - market: `coupon_id + order_event_id + buyer_identifier`
  - dm fulfillment: `delivery_subject + recipient + message_digest`

Server behavior:

- first request executes,
- duplicates return prior result (no double-send/no double-pay).

## 7.5 WebSocket + Polling Parity

Continue dual-surface operation:

- WS for push (`connected`, `events/messages`, `heartbeat`),
- GET for fallback in constrained runtimes.

Requirement:

- semantic parity between WS streams and GET snapshots over same window.

---

## 8. Safebox-Specific Design Guidance

## 8.1 Agent API

- keep existing endpoints stable,
- add optional trust/delegation metadata fields instead of breaking schema,
- expose verification flags in responses where trust decisions occur.

## 8.2 Market Specs (MS Series)

For each market spec:

- define acceptance checks as machine-testable requirements,
- define rejection reasons and evidence obligations,
- define idempotency and stale-order behavior,
- include conformance test IDs from day one.

## 8.3 Operational Logging

Prefer structured logs:

- `op=<operation>`
- `status=<stage|result>`
- `actor=<identifier>`
- `reason=<error_or_policy_code>`
- `evidence_ref=<event/tx id>`

Avoid logging secrets (`access_key`, `nsec`, token material, full invoices).

---

## 9. Threat-Oriented Controls

Minimum controls mapped to known risks:

1. Confused deputy
- enforce explicit scopes and target binding on delegated actions.

2. Prompt/data injection in agent loops
- require provenance checks before tool/action execution from external content.

3. Replay
- nonce + expiry + idempotency keys for monetary and settlement actions.

4. Identity ambiguity
- resolve mentions/targets from authoritative identity fields, not inferred signer shortcuts.

5. Self-dealing market behavior
- prohibit self-trades in policy and conformance tests.

---

## 10. Adoption Roadmap

## Phase 1 (Now)

- keep current API stable,
- enforce profile bootstrap and market policy guardrails,
- keep WS and GET fallback parity,
- expand conformance coverage (already in progress).

## Phase 2 (Near-Term)

- implement delegation/provenance envelopes as optional fields,
- persist action evidence objects,
- publish evidence query endpoints for operator audits.

## Phase 3 (Mid-Term)

- formalize trust profile document for Safebox agents,
- introduce cryptographically verifiable delegation chains across multi-agent workflows,
- standardize inter-agent trust assertions for cross-instance cooperation.

---

## 11. Conformance Considerations

Future ToIP-aligned Safebox conformance should evaluate:

- identity continuity under key rotation,
- delegation validation and expiry enforcement,
- provenance completeness for settlement actions,
- idempotent behavior under retries/replays,
- reproducibility of market decisions from public and private evidence.

---

## 12. Decision Summary

Safebox does not need a disruptive protocol replacement to become ToIP-aligned.

The practical path is incremental:

- retain Nostr/Lightning primitives,
- add explicit delegation and provenance structures,
- harden market and payment workflows with machine-testable trust controls.

This approach preserves operational momentum while materially improving trust guarantees for autonomous agent commerce.
