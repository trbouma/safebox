# QR and NFC Unified Flow Design

## Overview

This specification defines a convergence strategy for Safebox QR and NFC interaction flows.

The core design decision is:

- NFC and QR SHOULD share the same downstream processing architecture.
- QR and NFC MUST remain distinct at the bootstrap security layer.

In practice, this means the system should stop treating QR and NFC as separate end-to-end protocols and instead treat them as two different ways of acquiring bootstrap material for the same server-driven flow engine.

NFC remains the cleaner operational reference because it already demonstrates a narrower and more robust pattern:

- acquire bootstrap material
- hand off quickly to a server endpoint
- resolve host, KEM, authorization, and delivery state on the server

QR should converge toward that same model, while adding stronger replay and misuse protections because QR bootstrap material is visually observable and therefore easier to capture, copy, and replay.

## Scope

This specification applies to:

- offer acceptance flows
- proof acceptance flows
- record request and presentation bootstrap flows
- scan-driven recipient and presenter flows
- `nauth`-based QR handshakes
- token-based NFC handshakes

This specification does not redefine:

- record formats
- grant and offer object structure
- attestation, recognition, or acceptance semantics
- Cashu proof lifecycle behavior

Those concerns are defined elsewhere in the spec set.

## Problem Statement

Safebox currently contains multiple flow families that have diverged over time:

- NFC token flows
- plain QR offer flows
- recipient-initiated QR request flows
- presenter/verifier QR request flows

The NFC flows remain comparatively stable because they are mostly token-to-server flows. The QR flows are more fragile because they currently depend on:

- scanner redirects
- browser-local websocket timing
- multiple partially overlapping receive pages
- browser-held KEM state
- relay and host reconstruction in multiple places
- compact versus full QR behavior

This creates architectural drift. The result is that QR flows are more vulnerable to regressions even when the underlying issuance, transmittal, and verification primitives remain sound.

## Design Principle

The unified design principle is:

- QR and NFC differ only in bootstrap acquisition.
- After bootstrap acquisition, they SHOULD pass through the same normalized flow contract.

This implies a layered model:

1. Bootstrap Acquisition Layer
- NFC reads bootstrap material from a local token.
- QR acquires bootstrap material from a scanned visual code.

2. Bootstrap Normalization Layer
- both NFC and QR are converted into a shared internal bootstrap object

3. Server Flow Engine
- the server validates bootstrap state
- resolves host and KEM context
- applies replay and freshness checks
- drives authorization and delivery

4. Delivery and Ingestion Layer
- the system performs transmittal
- the recipient or verifier polls or listens using one shared mechanism

## Canonical Flow Shape

All scan- or tap-initiated flows SHOULD be normalized into a shared bootstrap structure with fields such as:

- `flow_type`
- `bootstrap_type`
- `scope`
- `token` or `nauth`
- `origin_hint`
- `nonce`
- `requested_kind`
- `selected_label`
- `service_host`
- `requires_confirmation`

The exact transport encoding may differ between QR and NFC, but the internal processing contract should be the same.

## NFC as Reference Architecture

NFC flows should be treated as the reference behavior for bootstrap-to-server handoff.

As of the April 2026 regression pass, the NFC record flows are the reference implementation for the unified flow architecture. The validated baseline includes:

- NFC offer, same instance
- NFC offer, cross instance
- NFC proof/request, same instance
- NFC proof/request, cross instance
- original-record blob transfer through both offer and proof/request flows
- KEM-wrapped record payloads and original-record metadata

Current NFC behavior demonstrates these desirable properties:

- low browser complexity
- authoritative server-side processing
- host-aware token handling
- server-driven KEM resolution
- fewer websocket timing dependencies

The NFC implementation should therefore be treated as the behavior QR needs to converge toward, not merely as a parallel transport option.

The unified design therefore adopts the following rule:

- if a QR flow and an NFC flow perform the same business operation, they SHOULD converge on the same server-side handler after normalization.

Examples:

- QR offer acceptance and NFC offer acceptance should both normalize into the same offer-acceptance pipeline
- QR proof acceptance and NFC proof acceptance should both normalize into the same proof-acceptance pipeline
- QR request initiation and NFC request initiation should both normalize into the same request-start pipeline

## Canonical User Interaction Model

For interactive record exchange, the preferred user model is receiver-presented bootstrap:

- the receiving or requesting Safebox presents the bootstrap material
- the sending or presenting Safebox acquires it by NFC tap or QR scan
- the sender then transmits the record using the normalized server-side flow

This model is preferred because the receiver controls the receive context, nonce, replay policy, and KEM context.

For offers, this means:

- canonical NFC offer: the sender taps the receiver's NFC card/token
- canonical QR offer: the sender scans the receiver's QR code
- sender-presented QR offer: optional convenience mode only, not the canonical secure flow

Sender-presented QR is weaker because the visible QR can be photographed, copied, and replayed by an unintended party. It MAY be retained later as a constrained remote/convenience mode, but it should not drive the primary architecture.

## KEM Directionality

KEM direction depends on the flow:

- NFC offer encrypts to the receiver's KEM
- NFC proof/request encrypts to the requester's KEM

This distinction is important.

In an offer flow, the offered grant is being delivered to the receiving Safebox. The receiving Safebox's server KEM is therefore the correct encryption target.

In a proof/request flow, the requested record is being presented back to the requester/verifier. The requester/verifier Safebox's server KEM is therefore the correct encryption target.

The April 2026 NFC baseline implements this split:

- offer acceptance resolves recipient KEM from the target service host when browser KEM is unavailable
- proof/request acceptance injects the local requester server KEM into the proof request
- the presenting wallet returns KEM-wrapped transmittal records
- the requester decrypts `pqc_encrypted_payload` and `pqc_encrypted_original` using its local KEM secret

The canonical record transmittal envelope contains:

- `ciphertext`
- `kemalg`
- `pqc_encrypted_payload`
- `pqc_encrypted_original`, when original-record transfer metadata is present

This envelope shape is the target for QR convergence.

## QR Security Distinction

QR bootstrap material is visually observable and therefore more vulnerable than NFC bootstrap material.

A QR code may be:

- photographed
- screen-captured
- shoulder-surfed
- replayed later
- replayed by a different party

Therefore QR MUST NOT be treated as security-equivalent to NFC even if both reuse the same downstream processing pipeline.

The design rule is:

- same downstream architecture
- stronger QR bootstrap security policy

## QR Replay and Misuse Protection

QR bootstrap flows MUST implement replay protections.

### Required Controls

1. Short-lived nonce
- every QR bootstrap MUST include a nonce
- the nonce MUST be unpredictable
- the nonce MUST have a bounded TTL

2. Single-use consumption
- a consumed QR bootstrap nonce MUST be marked used
- replay attempts using the same nonce MUST be rejected

3. Flow binding
- the bootstrap MUST be bound to its intended flow type and scope
- a QR issued for one flow MUST NOT be replayable into a different flow

4. Context binding
- the bootstrap SHOULD include or resolve:
  - expected service host
  - expected kind
  - expected action

5. Server-side validation
- replay protection MUST be enforced by the server
- browser-only guards are insufficient

6. Optional explicit confirmation
- for higher-risk QR flows, the recipient SHOULD confirm:
  - issuer or requester identity
  - requested action
  - kind or label

### Stronger Pattern

The preferred QR model is:

- QR starts a time-bound, single-use handshake
- QR does not itself contain all authority needed to complete the action

In other words:

- QR SHOULD bootstrap a live challenge-response flow
- QR SHOULD NOT function as a durable bearer credential

## Full versus Compact QR Policy

Compact QR encoding is a transport optimization, not a flow identity.

Compact QR MUST NOT be used when it removes context required for:

- KEM resolution
- replay protection
- host binding
- service routing
- challenge-response completion

Accordingly:

- flows requiring host-sensitive KEM recovery SHOULD default to full QR
- compact QR MAY be allowed only when the remaining bootstrap data is still sufficient to complete the flow safely

The system SHOULD treat compact mode as an optional optimization rather than a default for high-context flows.

## Implemented Compact Receive-Offer QR

As of the April 2026 QR regression pass, Safebox implements a compact recipient-presented QR path for receiving an offered record.

This is the canonical QR offer flow:

- the receiving Safebox opens the grant list and chooses "Show QR to Receive Offer"
- the receiving Safebox generates a compact `safebox:nembed...` bootstrap QR
- the sending Safebox opens the specific offer record it wants to send
- the sending Safebox scans the recipient QR from that offer context
- the scanner resolves the compact bootstrap to the active recipient listener
- the existing offer auto-send path transmits the selected offer record

The compact QR does not contain the KEM public key and does not contain the full listener `nauth`. It contains only enough bootstrap data to resolve a live, server-owned receive context.

The QR payload is encoded as:

- URI prefix: `safebox:`
- compressed bech32 payload: `nembed...`

The current receive-offer bootstrap object uses compact keys:

- `v`: version, currently `1`
- `t`: protocol marker, currently `sb`
- `f`: flow marker, currently `ro` for receive offer
- `n`: nonce
- `h`: recipient service host
- `gk`: grant kind expected by the recipient
- `ok`: offer kind expected from the sender
- `l`: optional label hint
- `s`: optional scheme hint, emitted only when the recipient service is not HTTPS

The recipient stores the full listener state server-side using the nonce. The public resolver endpoint is:

- `GET /.well-known/safebox/receive-offer/{nonce}`

The resolver returns the active listener `nauth` and associated offer/grant metadata only while the bootstrap is fresh and unused.

The sender scanner handles `safebox:nembed...` by:

- parsing the compact bootstrap
- verifying the flow marker is receive-offer
- requiring the scan to originate from an offer context
- resolving the full listener `nauth` from the recipient host
- posting into `/records/offerlist-scan` with `recipient_initiated=1` and `recipient_mode=auto_send`

The specific offer page is the preferred sender context because it binds the scan to the exact record label being sent. Scanning a receive-offer QR outside an offer context MUST NOT trigger an automatic send.

The nonce lifecycle is:

- QR generation creates a short-lived bootstrap row
- stale rows are pruned opportunistically
- resolver access rejects expired rows
- resolver access marks the nonce consumed
- replay attempts are rejected

This pattern keeps the QR compact while preserving host binding, nonce freshness, server-owned listener state, and the existing KEM-based offer transmittal pipeline.

## Sender-Presented Offer QR

Sender-presented offer QR is a supported convenience mode for cases where the sender needs to show an offer from an iPad, desktop, kiosk, shared screen, or remote call and the recipient scans the sender's QR code to receive the record.

This mode is useful, but it is not the canonical secure QR offer flow. The canonical QR offer flow remains recipient-presented QR, where the receiver creates the receive context and the sender scans it from the selected offer page.

Sender-presented QR has a different risk profile because the QR is visually exposed by the sender. It may be copied, photographed, screen-captured, or replayed by an unintended party. For this reason, sender-presented QR MUST be treated as a constrained remote/convenience mode and MUST use stricter replay controls than NFC.

The sender-presented QR flow SHOULD reuse the same downstream offer delivery pipeline as recipient-presented QR and NFC offer:

- the sender selects the exact offer record to send
- the sender generates a short-lived sender-offer bootstrap QR
- the recipient scans the QR
- the recipient resolves the bootstrap to an active sender offer context
- the recipient authenticates or accepts the offer
- the sender transmits the selected record through the existing KEM-wrapped `/records/transmit` path
- the sender UI shows completion only after transmittal succeeds

The QR payload SHOULD use the same compact Safebox QR envelope:

- URI prefix: `safebox:`
- compressed bech32 payload: `nembed...`

The sender-offer bootstrap object SHOULD use compact keys:

- `v`: version, currently `1`
- `t`: protocol marker, currently `sb`
- `f`: flow marker, `so` for sender offer
- `n`: nonce
- `h`: sender service host
- `ok`: offer kind being offered
- `gk`: grant kind that will be delivered
- `l`: optional label hint for display only
- `s`: optional scheme hint, emitted only when the sender service is not HTTPS

The compact QR MUST NOT contain the KEM public key and SHOULD NOT contain the full sender `nauth`. It should contain only enough information to resolve a live, server-owned sender-offer context.

The public resolver endpoint SHOULD be:

- `GET /.well-known/safebox/send-offer/{nonce}`

The resolver SHOULD return the active sender offer `nauth` and associated metadata only while the bootstrap is fresh and unused. Resolver output may include:

- `nauth`
- `offer_kind`
- `grant_kind`
- `label`
- `host`

The nonce lifecycle MUST be:

- QR generation creates a short-lived sender-offer bootstrap row
- stale rows are pruned opportunistically
- resolver access rejects expired rows
- resolver access marks the nonce consumed
- replay attempts are rejected

The scanner SHOULD dispatch compact Safebox QR payloads by flow marker:

- `f = "ro"` routes to the receive-offer resolver and selected sender offer context
- `f = "so"` routes to the send-offer resolver and recipient accept context

The recipient scanner handling a sender-presented QR SHOULD:

- parse the compact bootstrap
- verify the flow marker is sender-offer
- resolve the full sender offer context from the sender host
- route into the offer acceptance path using the resolved `nauth`
- rely on the established accept/transmit handshake rather than trusting the QR alone

The sender UI SHOULD make the security posture explicit. Suggested language:

- "Sender QR is convenient for remote issuance. Anyone who can see or copy this QR may attempt to claim the offer. Use only for short-lived, intended-recipient interactions."

The first implementation MAY keep the sender browser page open and use the existing sender listener to complete the offer, provided that:

- the QR is compact and resolves through a server-side nonce
- the nonce is short-lived and single-use
- KEM resolution remains server-owned when browser KEM state is unavailable
- success is shown only after `/records/transmit` succeeds

A later production-grade implementation SHOULD move more of the sender-offer intent into server-owned state so that the browser is used primarily for display and status rather than orchestration.

## Server-Owned KEM Resolution

Critical KEM resolution SHOULD be server-owned.

The browser MAY surface:

- `kem_public_key`
- `kemalg`

but the server SHOULD remain capable of resolving KEM material from authoritative hints such as:

- service host
- relay-derived origin
- recipient transmittal identity
- known wallet service metadata

This avoids making successful completion depend on:

- browser timing
- websocket ordering
- ephemeral in-memory page state

The rule is:

- browser-provided KEM is an optimization
- server-side KEM recovery is the reliability baseline

## Unified Receive and Delivery Model

Safebox SHOULD converge on one receive-side delivery model per flow class.

The current pattern of having multiple overlapping receive pages and websocket paths increases regression risk.

For each flow family, there should be:

- one canonical scan entry
- one canonical authorization response path
- one canonical transmittal listener
- one canonical ingest path

Legacy alternate routes MAY remain temporarily for compatibility, but SHOULD be treated as migration shims rather than equal first-class implementations.

## Recommended Refactor Direction

### Phase 1: Normalize Bootstraps

Introduce a shared normalized bootstrap object for all QR and NFC initiated flows.

This should include:

- flow type
- bootstrap source
- nonce
- host or origin hint
- selected kind
- selected label
- replay policy

### Phase 2: Converge Endpoints

Map QR and NFC into shared server-side handlers for:

- offer acceptance
- proof acceptance
- request initiation
- presentation initiation

The first QR convergence target should be recipient-presented QR, because it most closely matches the validated NFC model:

- receiver presents bootstrap
- sender acquires bootstrap
- sender transmits to receiver

Sender-presented QR should be deferred until the canonical NFC and recipient-presented QR paths are stable.

### Phase 3: Serverize Critical State

Move critical state ownership away from browser pages where feasible:

- KEM resolution
- replay ledger
- bootstrap freshness
- consumed bootstrap tracking
- service host resolution

### Phase 4: Retire Duplicated QR Paths

Deprecate older QR-only receive paths once canonical paths are stable.

The objective is to reduce:

- route branching
- websocket duplication
- mixed legacy and new semantics

Legacy sender-presented QR offer paths SHOULD NOT be treated as equivalent to the canonical recipient-presented flow. If retained, they should be marked as remote/convenience flows and protected with shorter TTLs, single-use nonce consumption, and explicit receiver confirmation.

## Security Considerations

### NFC

NFC is not inherently secure, but it is more proximity-constrained than QR.

Residual NFC risks include:

- token cloning
- replay if tokens are durable
- device or middleware compromise

NFC flows SHOULD still use:

- short-lived bootstrap material where possible
- server validation
- anti-replay protections where stateful actions are involved

### QR

QR requires stricter security controls because it is observable.

QR security MUST assume:

- passive capture is easy
- delayed replay is plausible
- unintended observers may obtain bootstrap material

Therefore:

- QR bootstrap state MUST be single-use and time-bound
- QR flows SHOULD prefer challenge-response completion over bearer-style completion
- QR SHOULD use explicit confirmation for higher-risk actions

### Shared Rule

Reusing the same downstream server architecture does not mean assigning equal security assumptions to NFC and QR. The security distinction belongs at the bootstrap layer.

## Implementation References

- `/Users/trbouma/projects/safebox-2/docs/specs/NFC-FLOWS-AND-SECURITY.md`
- `/Users/trbouma/projects/safebox-2/docs/specs/OFFERS-AND-GRANTS-FLOWS.md`
- `/Users/trbouma/projects/safebox-2/docs/specs/NAUTH-EXTENSIBLE-HANDSHAKE.md`
- `/Users/trbouma/projects/safebox-2/docs/specs/RECORD-PRESENTATION-NAUTH-STRATEGY.md`
- `/Users/trbouma/projects/safebox-2/docs/specs/PROTOCOL-NORMALIZATION-RELAY-FIRST-KEM.md`
- `/Users/trbouma/projects/safebox-2/docs/specs/THREAT-MODEL.md`
