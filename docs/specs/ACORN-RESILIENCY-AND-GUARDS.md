# Acorn Resiliency And Guard Strategy

## Overview

Acorn is the wallet runtime used by Safebox to coordinate balances, proofs, record transfer, and relay-based messaging in a distributed environment. It is intentionally designed with defensive controls because real deployments are noisy: relays can stall, websocket clients can disconnect mid-flow, mints can time out, and dependent services can return partial or conflicting state.

This document describes the major runtime guards, why they exist, and how rollback/recovery is handled when failures occur.

## Scope

This specification focuses on:

- Application-level safety controls in Acorn and related flow handlers.
- Behavior under unreliable infrastructure (network drops, relay delays, mint failures).
- Behavior under potentially adversarial conditions (replay, race, stale state, malformed input).
- Rollback and fail-safe expectations for payment and record workflows.

This document does not define cryptographic primitives or transport protocols; those are covered in related specs.

## Design Assumptions

Acorn assumes the following can happen at any time:

- Websocket sessions are interrupted without proper close frames.
- External mint endpoints may timeout or respond inconsistently.
- Relay event visibility may be delayed or reordered.
- Multiple concurrent operations may target the same wallet state.
- UI/browser behavior may duplicate requests due to refresh, retry, or reconnect.

Given these assumptions, Acorn prefers:

- conservative state transitions,
- explicit coordination guards,
- idempotent handling where feasible,
- and safe failure over optimistic continuation.

## Guard Categories

### 1. Concurrency Guards (Wallet Locking)

Acorn uses a wallet lock record to serialize critical state mutation paths.

Why:

- Prevents concurrent proof mutations and conflicting balance state updates.
- Reduces race conditions across overlapping async flows (NFC, invoice settlement, webhook-style notifications).

Current behavior:

- Attempt lock acquisition with bounded retries.
- If lock remains held beyond threshold, force-seize logic can recover progress.
- Lock acquisition and release now emit timing telemetry (wait and hold durations) to identify contention bottlenecks.

Tradeoff:

- Higher safety and consistency at the cost of occasional wait latency under concurrent load.

### 2. Input and State Guards

Flow handlers validate required fields and branch based on explicit state/status values before mutating wallet state.

Why:

- Prevents malformed, stale, or incomplete payloads from advancing a flow.
- Avoids ambiguous transitions when only partial data is available.

Examples:

- Required token/payload checks before settlement calls.
- Explicit status branching (`OK`, `PENDING`, `ERROR`, timeout).
- UI-side preflight checks before NFC actions proceed.
- Proof-safety audit gates before destructive proof mutation (`swap`/`consolidate`) to fail closed on invalid or ambiguous proof state.
- Non-destructive proof replacement requirement: existing proofs are not deleted/overwritten until replacement proofs are confirmed non-empty and persistence checks pass.

### 3. Transport/Session Guards

Websocket endpoints are hardened for abrupt disconnects and reconnection churn.

Why:

- Browser/mobile websocket behavior is non-deterministic in weak network conditions.
- A normal client disconnect should not cascade into noisy server-side exception traces.

Current behavior:

- Catch and degrade gracefully on disconnect during initial send and heartbeat send.
- Remove disconnected sockets from connection registries.
- Avoid treating transport disconnect as business-logic failure.

### 4. Retry, Timeout, and Degrade-Mode Guards

External calls (mints, relay queries, blob fetches, websocket notifications) are treated as fallible.

Why:

- Hard dependency failure is common in distributed systems and should not corrupt wallet state.

Current behavior:

- Retry with bounded attempts where safe.
- Emit explicit timeout/failure statuses upstream for operator/user visibility.
- Use fallback channels (for example status/notify combinations) when primary async signaling is delayed.

### 5. Flow Integrity Guards (NFC / QR / Record Transfer)

Interactive flows are guarded against stale session state, duplicate completion signals, and partial transfer conditions.

Why:

- NFC and QR operations are user-driven, timing-sensitive, and prone to duplicate triggers.

Current behavior:

- Completion path deduping in UI signaling (avoid duplicate success sequence on dual signal arrival).
- Explicit card-validity/secret checks in NFC paths.
- nAuth/nonce-based sequence constraints to limit unintended multi-responder completion.
- Non-fatal offer ingest fallback on decrypt mismatch to avoid dropping valid records.
- Payload normalization before persistence/render to prevent raw envelope leakage in UI.
- Signed-event validation guards so plain-text/JSON payloads are not misclassified as invalid events.

## Adversarial Environment Considerations

Acorn is designed so that infrastructure trust is limited and payload/control validation occurs in application logic.

Defensive posture includes:

- Signature and payload checks before sensitive operations.
- Scoped secrets and rotating credentials for NFC card pathways.
- Treating all upstream channels (relay, mint, websocket transport) as potentially delayed, unavailable, or misleading until validated.

This does not claim perfect Byzantine fault tolerance; it is pragmatic hardening for real-world hostile or unstable conditions.

## Rollback And Recovery Strategy

### Core Principle

If an operation cannot be confirmed as committed safely, do not mark it complete.

### Payment Flows

Payment flows should progress through explicit stages:

1. Accepted (request parsed and validated).
2. Processing (external dependency call in progress).
3. Settled (proofs/token state mutation confirmed).
4. Notified (user-facing completion signal emitted).

Rollback expectation:

- If failure occurs before settle confirmation, remain in non-final state and report retryable error.
- If failure occurs after external debit but before local finalization, recovery paths should reconcile based on source-of-truth state and avoid double-credit or silent loss.

### Record/Blob Transfer Flows

Rollback expectation:

- If blob retrieval/transfer fails, do not mark record transfer complete.
- Keep original flow resumable where possible.
- Return explicit failure status rather than implicit success.

### Lock-Guarded Rollback

On exception in lock-guarded critical sections:

- Ensure release path executes (`finally` semantics).
- Avoid partial in-memory mutations being treated as committed state.
- Emit structured logs enabling replay/reconciliation analysis.

## Observability Requirements

Operational confidence depends on telemetry for:

- Lock wait duration (`wait_ms`) and hold duration (`held_ms`).
- Timeout rates by operation type (mint, relay, blob, websocket notify).
- Settlement latency distribution (accepted -> settled).
- Rollback/failure counts and recovery outcome.

These signals are required to distinguish:

- true functional failures,
- expected transient degradation,
- and capacity/concurrency bottlenecks.

## Operational Guidance

- Treat repeated lock seizing as a performance/reliability smell; investigate long holders first.
- Keep retries bounded to avoid hidden infinite loops.
- Prefer explicit state messages to users over optimistic completion text.
- Validate end-to-end with failure injection (relay outage, mint timeout, websocket disconnect, client refresh mid-flow).

## Security Considerations

- Guards reduce but do not eliminate loss/corruption risk under severe partial failure.
- Rollback behavior must never reveal sensitive payloads in logs.
- Recovery tooling must preserve evidence and avoid destructive auto-repair.
- Operator runbooks should define when manual reconciliation is required.

## Implementation References

- `safebox/acorn.py`
- `app/tasks.py`
- `app/routers/safebox.py`
- `app/routers/records.py`
- `app/templates/access.html`
- `app/templates/pos.html`
