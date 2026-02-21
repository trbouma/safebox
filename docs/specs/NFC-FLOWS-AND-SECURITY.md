# NFC Flows and Security

## Introduction

Safebox uses a software-defined NFC card model to provide near full wallet functionality on inexpensive commodity tags such as NTAG215. In practice, this means a user can carry a low-cost NFC card and still perform core wallet operations without requiring their phone at the moment of interaction.

With a provisioned card, Safebox supports card-mediated:

- Logging into an NFC-enabled web app session
- Sending payments
- Receiving/requesting payments
- Offering records
- Requesting/presenting records

This enables practical "card-only at point of interaction" usage for payments and record exchange, while Safebox services handle secure vault messaging, authorization, and settlement in the background.

Safebox also uses a self-issuance model. The holder issues their own cards from the wallet and controls lifecycle state through secret rotation:

- A user can issue multiple cards.
- Each issued card can have its own unique PIN.
- The user can rotate the active secret to revoke previously issued cards.
- Rotation invalidates any old card payloads still in circulation.

This gives users direct control to activate new cards and revoke any and all prior cards without relying on specialized secure hardware.

## Key Takeaways

- Safebox NFC works with inexpensive NTAG215 cards and similar commodity NFC tags.
- A provisioned card can drive payments and record exchange flows at the point of interaction.
- A cardholder can log into an NFC-enabled Safebox web app directly with the card.
- Card validity is controlled in software through an active secret mapping, not secure card hardware.
- Users can self-issue multiple cards and revoke all older cards by rotating the active secret.
- Multiple cards can be active at once, each with a distinct PIN, while sharing the current active secret set.
- QR flows remain independent and continue working even when NFC cards are rotated/revoked.

## Overview

This document defines how Safebox NFC works today for:

- Card issuance and rotation
- NFC login
- NFC payment flows (request/receive and send)
- NFC record flows (offer and request/present)

It also describes the active-secret security model and failure behavior.

## Resiliency Overview for NFC Payments

NFC payment execution in Safebox is intentionally designed as a loosely-coupled, asynchronous workflow across multiple independently failing components:

- Browser/NFC runtime
- Safebox web/API service
- Vault endpoints (`/.well-known/*`)
- NWC relay messaging
- Wallet settlement logic (Cashu/Lightning)
- Optional blob/record relay paths for related flows

Because these components do not share a single transactional boundary, resiliency depends on explicit coordination states and compensating behavior rather than synchronous request/response assumptions.

### Why Loose Coupling Is Required

NFC interactions are short-lived, local trigger events, while settlement and secure messaging may complete later and across different services. Attempting strict coupling would make the system brittle to:

- mobile/browser backgrounding
- relay jitter or temporary partition
- vault endpoint timeout/retry conditions
- asynchronous wallet settlement latency

Safebox therefore treats NFC as an initiation signal and drives completion via asynchronous status channels.

### Coordination Strategy

Safebox coordinates loosely-coupled services with these core patterns:

1. Canonical staged lifecycle:
   - accepted (`PENDING`)
   - processing
   - terminal (`OK` or `ERROR`)
2. Explicit terminal signaling:
   - settlement completion/failure is sent on notify/status channels
   - UI should never treat initial acceptance as final success
3. Authoritative endpoint model:
   - preflight checks can be advisory for resilience
   - final trust decision remains at authoritative vault validation
4. Time-bounded waiting:
   - no indefinite waits in critical loops
   - bounded listener and settlement timeouts with explicit error outcomes
5. Timing-window tolerance:
   - short lookback windows for relay subscription (`since = now - small delta`)
   - reduces missed-event stalls from timestamp granularity
6. Compensating actions for uncertain delivery:
   - rollback/recovery records when ecash delivery confirmation is uncertain
   - preserves recoverability rather than silent proof loss

### Delay and Failure Handling Model

Each leg of the flow should be treated as potentially delayed, duplicated, or dropped.

- Delayed:
  - continue processing within bounded timeout windows
  - keep UI in explicit in-progress state
- Dropped:
  - surface terminal error and preserve artifacts needed for retry/recovery
- Duplicated:
  - rely on idempotent/guarded processing where available
- Partitioned:
  - fail fast where security requires certainty
  - otherwise continue to authoritative validation and report advisory degradation

### Operational Resiliency Requirements

Production NFC operation should include:

- independent relay and vault health monitoring
- retry/backoff on networked calls
- structured logs with correlation for stage transitions
- explicit timeout values per stage
- recovery runbook for uncertain delivery states
- user-facing status language that distinguishes:
  - request accepted
  - settlement in progress
  - settlement complete/failed

### Resulting System Properties

With the above strategy, Safebox NFC payment flows aim to provide:

- graceful degradation under partial outages
- bounded failure rather than indefinite hanging
- recovery paths for uncertain transfer states
- consistent user semantics despite asynchronous backend coordination

## Core Security Model

Safebox uses an application-layer card token model:

1. A card payload contains an encrypted value `k` which decrypts to:
   - `nwc_secret:pin`
2. `nwc_secret` is looked up in `NWCSecret` to resolve the active target `npub`.
3. If no active mapping exists, the card is invalid.

### Single Active Secret per Safebox

Each Safebox has one active NWC secret mapping used for NFC card operations.

- Reusing cards:
  - Multiple physical cards can carry the same `nwc_secret`.
- Rotation:
  - Rotating creates a new `nwc_secret` mapping for that `npub`.
  - Previously issued cards with the old secret fail immediately.

### Cards Can Have Different PINs

The encrypted card payload includes `secret:pin`.
This means multiple cards can share the same active secret while using different PIN values.

- Secret identifies which wallet/card-set is valid.
- PIN is an additional per-card user gate.

## Issuance and Rotation

Holder endpoint:

- `GET /safebox/issuecard`

Behavior:

1. Fetch active `nwc_secret` for the safebox.
2. If rotate requested, generate/store a new `nwc_secret`.
3. Generate `secure_pin`.
4. Encrypt `"{nwc_secret}:{secure_pin}"` with service key (`SERVICE_NSEC`, NIP-44).
5. Build `nembed` token with:
   - `h` host binding
   - `k` encrypted payload
   - `a` default amount hint
   - `n` defaults metadata
6. User writes this `nembed` to one or more cards.

Operational result:

- No rotation: newly written cards remain compatible with existing active cards.
- Rotation: old cards are revoked by design.

## Card Validation and Fast-Fail

Public validation endpoint:

- `POST /.well-known/card-status`

Request must include signed token fields:

- `token`
- `pubkey`
- `sig`

Validation sequence:

1. Verify signature over token.
2. Decrypt token payload.
3. Resolve `nwc_secret` in active mapping table.
4. Return active status or reject.

Reject behavior:

- Rotated/revoked/unknown secret returns invalid-card response.
- NFC flows should stop immediately and show user-facing error.
- QR flows are not affected.

## NFC Login Flow

Endpoint:

- `POST /safebox/loginwithnfc`

Sequence:

1. Client submits NFC `nembed`.
2. Server parses token and validates host.
3. Server decrypts `k` and resolves `nwc_secret -> npub`.
4. If mapping exists, login proceeds and access token is issued.
5. If mapping does not exist, login fails (invalid/revoked card).

## NFC Payment Flows

### A. Request Payment (Receiver Reads Payer Card)

Client/API endpoint:

- `POST /safebox/requestnfcpayment`

Remote vault endpoint:

- `POST /.well-known/nfcvaultrequestpayment`

Flow:

1. Receiver taps payer NFC card and gets token.
2. Receiver submits token + amount/currency/comment.
3. Server parses token host and signs token payload.
4. Server forwards to payer vault endpoint.
5. Vault validates token/signature, decrypts card payload, resolves active secret.
6. Vault emits NWC instruction to payer wallet.
7. Payer wallet executes payment path (ecash or lightning workflow).
8. Receiver gets completion updates (notify/status channel) and balance refresh.

Failure mode:

- If card secret is stale/rotated, vault rejects early and request fails immediately.

### Payment Transaction Lifecycle and Status Semantics

Safebox NFC payment processing is asynchronous and should be interpreted as a staged lifecycle rather than a single atomic HTTP response.

#### Canonical Stages

1. Request accepted:
   - The initiating endpoint accepts the NFC request and returns `PENDING`.
   - Meaning: the request is authorized and queued, not settled.
2. Card wallet confirmation:
   - Card-side wallet receives and validates the instruction.
   - UI guidance: "Awaiting card wallet confirmation..."
3. Processing:
   - Wallet executes settlement path (ecash transfer or invoice path).
   - UI guidance: "Processing payment..."
4. Settlement complete:
   - Completion is signaled by notify/status events (`OK`/`ADVISORY`) and balance update.
   - UI may render final success.
5. Settlement failed:
   - Errors are surfaced as `ERROR` with detail; request should not be marked complete.

#### POS/NFC Status Handling

- POS should not mark payment complete on initial NFC request acceptance.
- POS should treat initial response as `PENDING`.
- POS should finalize only on asynchronous settlement notifications (`action=nfc_token` with terminal status).

### B. Send Payment (Sender Reads Recipient Card)

Client/API endpoint:

- `POST /safebox/paytonfctag`

Remote vault endpoint:

- `POST /.well-known/nfcpayout`

Flow:

1. Sender taps recipient NFC card.
2. Sender submits token + amount/currency/comment.
3. Server parses token and computes SAT amount.
4. Server signs token and posts to recipient vault.
5. Vault validates/decrypts token, resolves active recipient secret.
6. Vault starts recipient-side invoice/ecash handling.
7. Sender completes payment and both wallets update.

Failure mode:

- Stale/rotated card secret fails before payout processing.

### Ecash Delivery Safety, Rollback, and Recovery

To reduce proof-loss risk during network interruption or UI refresh, Safebox applies delivery safeguards in ecash send paths.

#### Problem Addressed

In ecash workflows, a token can be issued (spending sender proofs) before remote delivery confirms. If transport fails at that point, funds can appear lost unless explicitly recovered.

#### Implemented Guardrails

1. Delivery confirmation check:
   - After token issuance, Safebox attempts remote delivery and tracks confirmation.
2. Best-effort rollback on delivery failure:
   - If delivery is not confirmed, Safebox attempts local self-accept (`accept_token`) of the same token to restore wallet state.
3. Recovery record on rollback uncertainty:
   - If rollback cannot be confirmed, Safebox persists a recovery artifact record (`ecash-recovery-*`) containing:
     - token payload
     - amount and comment
     - destination metadata (vault URL or recipient/relays)
     - timestamp

#### Operational Outcome

- Most transient delivery failures recover automatically through rollback.
- Remaining uncertain cases are explicitly recoverable using stored recovery artifacts instead of silent proof loss.

## NFC Record Flows

### A. Offer Record over NFC

Client/API endpoint:

- `POST /records/acceptoffertoken`

Remote vault endpoint:

- `POST /.well-known/offer`

Flow:

1. Offerer prepares `nauth` context.
2. Offerer taps recipient card and captures token.
3. `acceptoffertoken` parses token and runs card preflight:
   - `POST /.well-known/card-status`
4. Preflight is advisory for stability:
   - If it passes, proceed normally.
   - If it fails due to timeout/network/proxy transport issues, continue with warning logs.
5. Service signs token and calls `/.well-known/offer` (authoritative check).
6. Vault validates token, resolves active secret, and emits NWC `offer_record`.
7. Recipient wallet handles offer flow and transmittal.

Security note:

- Offer flow security does not rely on preflight success.
- The authoritative decision is made by `/.well-known/offer` validation.
- This avoids false negatives from transport-only failures while preserving cryptographic checks.

### B. Request/Present Record over NFC

Client/API endpoint:

- `POST /records/acceptprooftoken`

Remote vault endpoint:

- `POST /.well-known/proof`

Flow:

1. Requester prepares `nauth`, kind, label, and PIN.
2. Requester taps presenter card and captures token.
3. `acceptprooftoken` parses token and runs card preflight:
   - `POST /.well-known/card-status`
4. Preflight is advisory for stability:
   - If it passes, proceed normally.
   - If it fails for transport reasons, continue with warning logs.
5. Service signs token and calls `/.well-known/proof` (authoritative check).
6. Vault validates token, checks PIN, and emits NWC `present_record`.
7. Presenter wallet returns records over transmittal channels.
8. Requester receives, verifies, and renders records (including original blob flow when present).

## PIN Behavior

PIN is checked in proof/presentation-style authorization flows and can be used as a gate before sensitive actions.

Key points:

- PIN is card-specific and embedded with the active secret.
- PIN mismatch can reject or downgrade authorization depending on vault policy.
- Secret validity and PIN validity are separate checks.

### PIN-Provided and PIN-Not-Provided Flows

Safebox now supports explicit user decisioning in record request UX.

1. PIN provided and valid:
   - `/.well-known/proof` returns `status=OK`.
   - Request proceeds normally.
2. PIN provided but invalid:
   - `/.well-known/proof` returns non-OK (typically `WARNING` / invalid PIN detail).
   - Client shows a confirm dialog: "Invalid PIN. Continue anyway?"
   - If user cancels, request stops.
   - If user confirms, request remains active and waits for record delivery based on vault policy.
3. PIN not provided (empty/omitted):
   - Treated as PIN mismatch by vault-side PIN check.
   - Client receives non-OK detail and applies the same continue/cancel confirm flow.

Operationally, this keeps PIN as a user-level control while allowing controlled bypass where policy permits.

## Record Flow Stability Hardening

Recent changes were made specifically to reduce exploitability from brittle transport behavior and to improve reliability in heterogeneous browser/proxy setups.

### 1. Preflight Converted to Advisory

Endpoints:

- `POST /records/acceptoffertoken`
- `POST /records/acceptprooftoken`

Behavior:

- Card-status preflight (`/.well-known/card-status`) is still executed.
- Preflight failure no longer hard-fails the flow.
- The flow proceeds to authoritative vault endpoints (`/.well-known/offer`, `/.well-known/proof`).

Reason:

- Preflight can fail for non-security reasons (proxy header mismatch, transient network failures, timeout).
- Hard-failing at preflight caused user-visible regressions in NFC offer/request while QR flows still worked.
- Authoritative vault validation already enforces signature + token + secret checks.

### 2. Authoritative Validation Remains Unchanged

- Offer vault (`/.well-known/offer`) and proof vault (`/.well-known/proof`) remain the enforcement points.
- Invalid/revoked card secrets still fail.
- Signature verification still required.
- Decrypt/parse errors still fail.

### 3. Better Upstream Error Propagation

For vault HTTP errors, Safebox now returns upstream `detail` when available instead of generic HTTP-only text.

Outcome:

- Users get actionable failures (for example invalid card/invalid PIN specific detail).
- Operators can correlate UI failures with backend logs quickly.

### 4. Browser Stability and Transport Safety

Record templates now normalize websocket URL usage on HTTPS pages:

- If page protocol is HTTPS and websocket base contains `ws://`, client upgrades to `wss://` before connect.

Outcome:

- Prevents mixed-content websocket blocks in stricter desktop browsers.
- Keeps QR-driven and NFC-assisted offer/request record flows consistent across Chrome/Safari/mobile.

### 5. Legacy Browser PDF Fallback

For original-record rendering in offer/grant views, Safebox now uses a compatibility fallback when modern PDF rendering is unavailable.

Behavior:

- Primary path: render PDF inline with PDF.js (single-page view with Prev/Next controls).
- Fallback path: if PDF.js is unavailable or PDF rendering fails, show:
  - "PDF preview unavailable on this browser."
  - "Open/Download Original PDF" link to the original blob endpoint.

Outcome:

- Older browsers/devices (for example older Chromebook builds) can still access original records.
- Record exchange remains functional even when inline PDF preview is unsupported.

## Stall Conditions and Mitigations

NFC flows are asynchronous and cross multiple systems (browser NFC, websocket channels, relays, vault endpoints, and wallet settlement loops). Stalls are typically caused by timing windows or transport-layer interruption, not cryptographic validation failures.

### A. UI waits on non-terminal status

Condition:

- Client receives `PENDING`/intermediate status but never receives terminal status (`OK` or `ERROR`) on the same channel.

Observed impact:

- UI remains in states such as "Awaiting wallet confirmation..." even though payment or record processing completed.

Mitigations:

- Canonical status lifecycle documented and enforced (`PENDING` -> processing -> terminal).
- POS/NFC flows now emit explicit terminal notify events on settlement completion/failure.
- UI includes fallback completion logic from balance/status deltas when notify delivery is delayed.

### B. Same-second event miss in relay listeners

Condition:

- Listener starts with `since=now` and misses events created in the same second due to timestamp granularity and ordering.

Observed impact:

- Offer/request/grant websocket listeners appear to "hang" until timeout.

Mitigations:

- Listener start now uses a short lookback window (`since = now - 5s`) in critical NFC/record paths.
- Poll cadence reduced (for example from 5s to 1s in record websocket loops) for faster progression.

### C. Unbounded wait loops in record offer handling

Condition:

- NWC `offer_record` path waited indefinitely for transmittal records with no timeout.

Observed impact:

- Card-driven offer flow appears stalled forever if no matching transmittal event arrives.

Mitigations:

- Added hard timeout using `LISTEN_TIMEOUT`-based bound.
- On timeout, flow fails explicitly instead of hanging indefinitely.

### D. Slow payment settlement polling

Condition:

- Settlement polling at fixed coarse intervals increases post-payment latency.

Observed impact:

- Users perceive NFC as slow even when remote wallet confirms quickly.

Mitigations:

- Adaptive poll schedule in payment settlement:
  - fast early window (1s)
  - moderate middle window (2s)
  - slower late window (3s)
- Preserves reliability while reducing average confirmation latency.

### E. Preflight transport fragility

Condition:

- Card-status preflight fails due to timeout/proxy/network while card is actually valid.

Observed impact:

- Flow aborts before authoritative validation endpoint is reached.

Mitigations:

- For record NFC paths, preflight is advisory and authoritative vault endpoints remain the source of truth.
- Upstream vault error detail is propagated so operator/user can distinguish network issues vs card invalidity.

### F. Websocket mixed-content and browser policy mismatch

Condition:

- HTTPS page attempts `ws://` connection in stricter browsers.

Observed impact:

- Authentication/listener websocket never opens, resulting in apparent stall.

Mitigations:

- Browser-side websocket URL normalization enforces `wss://` on HTTPS pages.
- Maintains compatibility for localhost (`ws://`) and deployed HTTPS (`wss://`) environments.

### Operator Diagnostics for Stall Triage

When diagnosing a suspected stall, check these in order:

1. Browser console: websocket connect/open errors, mixed-content blocks, NFC API errors.
2. Vault endpoint logs: `/.well-known/card-status`, `/.well-known/offer`, `/.well-known/proof`, `/.well-known/nfcvaultrequestpayment`.
3. NWC listener logs: instruction receipt (`present_record`, `offer_record`, `pay_invoice`, `pay_ecash`) and completion/timeout.
4. Relay timing: event timestamps around listener start (`since`) boundaries.
5. UI terminal state path: verify notify/status terminal events are received (`OK`/`ERROR`).

## User Experience Requirements

For NFC actions, UI should:

1. Show immediate success/failure status after submit.
2. For record PIN failures, use confirm-style user decisioning instead of hard-stop alerts.
3. For non-PIN failures, show explicit error detail from vault responses when available.
4. Keep QR workflows unchanged and independent from NFC card rotation state.

## Operational Guidance

- Protect `SERVICE_NSEC`; compromise affects NFC token trust boundary.
- Keep `NWCSecret` mapping authoritative and auditable.
- Use structured logging for:
  - signature failures
  - decrypt failures
  - invalid/revoked secret lookups
  - upstream timeout/network errors
- Rotate secret when card set should be invalidated.
- Reissue cards after rotation.

## Endpoints Reference

Holder/client:

- `/safebox/issuecard`
- `/safebox/loginwithnfc`
- `/safebox/requestnfcpayment`
- `/safebox/paytonfctag`
- `/records/acceptoffertoken`
- `/records/acceptprooftoken`

Vault/public:

- `/.well-known/card-status`
- `/.well-known/nfcvaultrequestpayment`
- `/.well-known/nfcpayout`
- `/.well-known/offer`
- `/.well-known/proof`
