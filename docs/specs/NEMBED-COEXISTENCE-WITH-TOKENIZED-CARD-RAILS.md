# nembed Coexistence With Tokenized Card Rails

## Overview

This specification compares current digital-wallet card virtualization patterns with Safebox card-token flows, then proposes a coexistence model where `nembed` can operate alongside existing tokenized payment rails without replacing them.

The goal is dual-path acceptance:

- keep compatibility with incumbent tokenized card transactions, and
- add a parallel `nembed` path for sovereign wallet and record-capable interactions.

## Scope

In scope:

- conceptual comparison between mainstream tokenized card wallet flows and Safebox NFC/NWC flows
- a coexistence architecture for `nembed` in merchant and wallet contexts
- transaction lifecycle mapping, failure semantics, and rollout phases

Out of scope:

- changes to external card-network protocols
- processor/acquirer-specific contract requirements
- legal or scheme certification procedures

## Current Tokenized Card Virtualization Model (Industry Baseline)

Modern mobile wallets typically virtualize a physical card into a device-specific payment credential. The usual flow is:

1. Provisioning:
   - card is verified by issuer and token service provider
   - wallet stores a tokenized card identifier + cryptographic material in secure hardware/software boundary
2. Transaction initiation:
   - user authenticates device/card app
   - wallet generates transaction cryptogram
3. Network authorization:
   - merchant/acquirer sends authorization through card rails
   - issuer approves/declines
4. Settlement:
   - clearing/settlement follows standard rail lifecycle

Primary strengths:

- broad merchant acceptance
- mature dispute and operational frameworks
- familiar UX for tap/pay

Primary constraints:

- payment-only orientation
- dependency on centralized issuers/processors
- limited native support for generalized secure record exchange

## Safebox Virtualization Model (Current)

Safebox virtualizes card behavior at the application layer:

1. NFC card stores an encrypted payload containing active secret + PIN context.
2. Vault/NWC services resolve secret-to-wallet mapping and authorize actions.
3. Actions can be payment or record flows (offer/request/present), not payment only.
4. Completion is asynchronous across relay/messaging/payment subsystems with explicit terminal status.

Strengths:

- supports payment + records under one interaction model
- card lifecycle controlled by secret rotation/revocation
- designed for unreliable distributed services with fallback/rollback behavior

Constraints:

- not automatically accepted by legacy payment terminals
- requires service reachability for vault/relay workflows

## Side-by-Side Functional Comparison

1. Trust anchor:
   - Tokenized card rails: issuer/network trust chain
   - Safebox: key ownership + service trust anchors + relay proofs
2. Credential form:
   - Tokenized card rails: network token + per-transaction cryptogram
   - Safebox: `nembed` payload + signed vault authorization + nauth/nwc messaging
3. Primary capability:
   - Tokenized card rails: payment authorization
   - Safebox: payment + record transfer/presentation
4. Failure model:
   - Tokenized card rails: synchronous auth response + settlement later
   - Safebox: asynchronous state machine with explicit intermediate states and rollback/recovery paths
5. Revocation:
   - Tokenized card rails: issuer/network lifecycle controls
   - Safebox: secret rotation invalidates prior cards immediately

## Proposed Coexistence Architecture

### Design Principle

Do not replace tokenized card flows. Add `nembed` as an additional credential lane available to wallets, merchants, or agents when supported.

### Capability Negotiation

At payment entry points (POS/app/API), negotiate path in this order:

1. If `nembed` is present and supported, offer:
   - `nembed-payment`
   - optional `nembed-record` extension
2. Else, fallback to existing tokenized card flow.
3. If both available, allow policy-based routing (merchant/user preference).

### Merchant-Side Abstraction

Define a payment-intent abstraction with normalized states:

- `CREATED`
- `PENDING_AUTH`
- `PROCESSING`
- `COMPLETED`
- `FAILED`
- `RECOVERABLE`

Map both rails into this same state model so UI and reconciliation are consistent.

### nembed Attachment Pattern

`nembed` can be attached as:

1. NFC payload (card tap)
2. QR payload (cross-device)
3. API field in wallet/agent request objects

Minimal envelope fields:

- issuer/service host hint
- encrypted credential blob
- optional defaults (amount, context)
- optional flow capability tags (`payment`, `record`, `hybrid`)

### Routing Decision Example

1. Terminal receives tap payload.
2. If payload parses as tokenized card only -> process standard rail.
3. If payload parses as `nembed` only -> process Safebox lane.
4. If dual payload supported -> select lane by policy:
   - lowest latency route
   - lower fee route
   - user-selected route
   - capability-required route (records require `nembed`)

## Coexistence With LNURL NFC Cards (Bolt Card Style)

### Context

LNURL-enabled NFC cards (commonly deployed as Bolt Card style flows) are already accepted by some Lightning-capable terminals. They are optimized for fast pay-by-tap user experience and broad compatibility in Lightning environments.

Safebox `nembed` should coexist with this model rather than replace it.

### Coexistence Strategy

At tap time, terminal/wallet software can detect capability and route accordingly:

1. If LNURL card payload is detected:
   - run LNURL/Bolt Card payment flow.
2. If `nembed` payload is detected:
   - run Safebox flow (`nembed-payment` and optional record extensions).
3. If both are present or available via profile lookup:
   - route by policy (merchant default, user preference, or capability requirement).

### Integration Patterns

1. Dual-reader terminal integration:
   - terminal plugin/service parses both LNURL and `nembed` payload classes.
   - emits a unified payment intent into one status machine.
2. Wallet-side abstraction:
   - mobile/web wallet wraps LNURL and `nembed` behind one “Tap to Pay/Request” API.
   - downstream route chosen by policy and context.
3. Progressive enablement:
   - keep existing Bolt Card terminal behavior unchanged.
   - add `nembed` as optional capability in the same terminal stack.

### Practical Routing Guidance

- Prefer LNURL lane when merchant terminal only supports payment settlement and no record exchange.
- Prefer `nembed` lane when:
  - record transfer/presentation is required,
  - secret-rotation card lifecycle controls are required,
  - asynchronous resiliency/rollback semantics are needed beyond payment-only flow.
- If a lane fails pre-auth checks, attempt controlled fallback only when policy allows and user context is preserved.

### Security and UX Considerations

1. Avoid silent cross-lane downgrade:
   - if user expects record-capable interaction, do not silently fallback to payment-only LNURL.
2. Keep lane-visible status:
   - surface which lane is active (`Lightning card` vs `Safebox nembed`) for operator and user clarity.
3. Maintain per-lane audit tags:
   - include lane identifier in logs/receipts/reconciliation events.

### Deployment Note

Coexistence with Bolt Card style terminals is a near-term interoperability path:

- preserves existing Lightning card acceptance,
- introduces `nembed` incrementally,
- allows merchants to enable advanced Safebox capabilities without replacing terminal fleets.

## Coexistence With Square NFC Terminal Environments

### Context

Square-managed NFC terminal environments are typically optimized for card-present and wallet-present payment acceptance through Square’s processing stack. To accept `nembed` tokens in this environment, integration should be designed as an adjacent capability, not a disruptive replacement.

### Integration Objective

Enable merchants to keep standard Square payment acceptance while adding a Safebox `nembed` lane for:

- sovereign wallet payment requests,
- optional record-capable interactions,
- card lifecycle controls based on secret rotation.

### Recommended Architecture

1. Companion app/service pattern:
   - Keep Square terminal flow unchanged for standard payments.
   - Add a companion service (mobile/web/POS sidecar) that can read NFC payloads and detect `nembed`.
   - Route `nembed` interactions to Safebox endpoints while preserving current terminal operations.
2. Intent orchestration layer:
   - Normalize both Square terminal outcomes and `nembed` outcomes into one merchant-side intent state model:
   - `CREATED -> PENDING_AUTH -> PROCESSING -> COMPLETED|FAILED|RECOVERABLE`
3. Policy routing:
   - If merchant chooses Square-only mode, process exclusively on existing rails.
   - If merchant enables hybrid mode, detect payload type and route:
     - standard card/wallet payload -> Square path
     - `nembed` payload -> Safebox path

### UX Guidance

1. Clear lane labeling:
   - Display active lane explicitly (for example, `Card Terminal` vs `Safebox nembed`) to avoid operator confusion.
2. Deterministic fallback:
   - If `nembed` lane fails before terminal authorization, allow configurable fallback to standard terminal payment.
   - If record-capable interaction is requested, do not silently downgrade to payment-only lane.
3. Reconciliation clarity:
   - Include lane identifier in transaction history and exports.

### Operational Considerations

1. Deployment model:
   - Start with selected merchants/devices in hybrid mode.
   - Validate latency, completion signaling, and supportability before broad rollout.
2. Reliability:
   - Treat `nembed` as asynchronous and status-driven.
   - Preserve rollback/recovery semantics for uncertain delivery states.
3. Compliance/logging:
   - Keep audit events separate by lane.
   - Ensure operator-visible records can demonstrate whether a transaction used terminal rails or Safebox `nembed`.

### Implementation Direction

Short term:

- add `nembed` detection and routing in a sidecar service near the terminal workflow.
- keep standard Square acceptance untouched.

Medium term:

- unify checkout state and receipt rendering across both lanes.
- provide merchant controls for lane preference and fallback policy.

## Transaction Semantics Alignment

To coexist safely, status semantics must align:

1. Initial acceptance is not completion.
2. Completion only on terminal confirmation from chosen rail.
3. Timeouts are explicit and user-visible.
4. Recoverable failures preserve replay or rollback artifacts.

For `nembed`:

- use explicit advisory/processing/terminal events
- retain rollback records for uncertain ecash delivery
- preserve idempotency keys for retries

For tokenized card rails:

- map network auth/decline and reversal states into same intent model

## Security Considerations

1. Credential separation:
   - tokenized card secrets and `nembed` secrets must remain isolated.
2. Anti-downgrade:
   - if a flow requires `nembed` capability (for records), do not silently downgrade to payment-only rail.
3. Replay resistance:
   - include nonce/session binding and strict terminal consumption rules for `nembed`.
4. Key management:
   - protect service keys; rotate active card secrets; maintain audit trails.
5. Privacy:
   - avoid exposing wallet-sensitive metadata in shared merchant logs.
6. Rollback readiness:
   - ensure recoverable artifacts are durable when transport success is uncertain.

## Deployment Approach

### Phase 1: Passive Coexistence

- support existing tokenized card flow unchanged
- add `nembed` parsing and capability detection only
- no routing to `nembed` by default

### Phase 2: Controlled Dual-Path

- enable policy-based routing for selected merchants/environments
- collect latency/success/failure metrics by lane
- run parity validation on reconciliation and completion signaling

### Phase 3: Feature Expansion

- enable `nembed` record-capable flows where required
- keep payment fallback to tokenized rails for broad acceptance

## Observability and Operations

Track by lane (`tokenized`, `nembed`) and by stage:

- auth start/success/fail
- processing duration
- terminal completion/failure
- timeout count
- rollback invoked/succeeded/failed

Operational dashboards should compare:

- success rate
- p95/p99 completion latency
- recoverable failure frequency
- user-abandonment during pending state

## Implementation References

- `docs/specs/CARD-TOKENIZATION-AND-NFC-PAYMENT-STRATEGY.md`
- `docs/specs/NFC-FLOWS-AND-SECURITY.md`
- `docs/specs/NWC-NFC-VAULT-EXTENSION.md`
- `docs/specs/NAUTH-PROTOCOL.md`
- `docs/specs/NEMBED-PROTOCOL.md`
- `docs/specs/ACORN-RESILIENCY-AND-GUARDS.md`
